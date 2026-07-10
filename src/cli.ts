#!/usr/bin/env node
import { Command } from "commander";
import { dirname, join } from "node:path";
import ora from "ora";
import { parseCurl } from "./parser/curl.js";
import { parseOpenAPIFromURL } from "./parser/openapi.js";
import { createProvider, VALID_MODELS } from "./analyzer/provider.js";
import { synthesizeFallbackPayloads } from "./analyzer/fallback.js";
import { executePayloads } from "./executor/runner.js";
import { calculateRiskScore, getRiskRating } from "./reporter/score.js";
import { logResult, logSummary, sanitizeTerminalText } from "./reporter/terminal.js";
import { writeMarkdownReport } from "./reporter/markdown.js";
import { writeJSONReport } from "./reporter/json.js";
import { buildFindings } from "./reporter/findings.js";
import { redactUrl } from "./security/redaction.js";
import { collectOption, parseRuntimeOptions, reachesFailureThreshold } from "./cli-options.js";
import type { Endpoint, Report, Vulnerability } from "./types.js";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const pkg = JSON.parse(readFileSync(join(__dirname, "..", "package.json"), "utf-8"));
const MODEL_LIST = [...VALID_MODELS].join(", ");
const program = new Command();

program
  .name("vuln-monkey")
  .description("AI-powered API security fuzzer")
  .version(pkg.version)
  .argument("[curl]", "curl command to fuzz")
  .option("--spec <url>", "OpenAPI/Swagger spec URL")
  .option("--model <model>", "claude-cli, gemini-cli, codex-cli, claude, gemini, openai, ollama, local", "claude-cli")
  .option("--output <dir>", "Report output directory", "./reports")
  .option("--concurrency <n>", "Parallel requests", "5")
  .option("--timeout <ms>", "Request timeout", "10000")
  .option("-H, --header <header>", "Header applied to every endpoint (repeatable)", collectOption, [])
  .option("--credential-origin <origin>", "Origin allowed to receive -H credentials (repeatable)", collectOption, [])
  .option("--allow-private", "Allow private/local target addresses", false)
  .option("--fail-on <severity>", "Exit non-zero at or above: low, medium, high, critical", "none")
  .option("--dry-run", "Generate payloads without firing", false)
  .action(async (curl, opts) => {
    if (!curl && !opts.spec) {
      program.error("Provide a curl command or --spec <url>");
    }
    if (curl && opts.spec) {
      program.error("Provide a curl command or --spec <url>, not both");
    }

    if (!VALID_MODELS.has(opts.model)) {
      program.error(`Invalid model "${sanitizeTerminalText(opts.model)}". Must be one of: ${MODEL_LIST}`);
    }

    let runtimeOptions: ReturnType<typeof parseRuntimeOptions>;
    try {
      runtimeOptions = parseRuntimeOptions(opts);
    } catch (err) {
      return program.error(sanitizeTerminalText(err instanceof Error ? err.message : String(err)));
    }
    const { concurrency, timeout, headerOverrides, credentialOrigins, failOn, outputDir } = runtimeOptions;
    if (opts.spec && Object.keys(headerOverrides).length > 0 && credentialOrigins.length === 0) {
      program.error("--credential-origin is required when using -H with --spec");
    }

    const startTime = Date.now();
    const model = opts.model;

    // Step 1: Parse input into endpoints
    const parseSpinner = ora("Parsing input...").start();
    let endpoints: Endpoint[];

    try {
      if (opts.spec) {
        endpoints = await parseOpenAPIFromURL(
          opts.spec,
          headerOverrides,
          credentialOrigins,
          opts.allowPrivate
        );
      } else {
        endpoints = [parseCurl(curl)];
      }
      if (endpoints.length === 0) {
        parseSpinner.fail("No endpoints found in spec");
        process.exitCode = 1;
        return;
      }
      endpoints = endpoints.map((endpoint) => {
        const canReceiveHeaders = !opts.spec
          || credentialOrigins.includes(new URL(endpoint.url).origin);
        return canReceiveHeaders
          ? {
              ...endpoint,
              headers: { ...endpoint.headers, ...headerOverrides },
              credentialHeaderNames: opts.spec
                ? [...new Set([
                    ...(endpoint.credentialHeaderNames ?? []),
                    ...Object.keys(headerOverrides),
                  ])]
                : endpoint.credentialHeaderNames,
            }
          : endpoint;
      });
      parseSpinner.succeed(`Parsed ${endpoints.length} endpoint(s)`);
    } catch (err) {
      parseSpinner.fail(`Parse failed: ${sanitizeTerminalText(err instanceof Error ? err.message : String(err))}`);
      process.exitCode = 1;
      return;
    }

    const target = opts.spec || endpoints[0]?.url || "unknown";
    let provider: ReturnType<typeof createProvider>;
    try {
      provider = createProvider(model);
    } catch (err) {
      console.error(`Provider initialization failed: ${sanitizeTerminalText(err instanceof Error ? err.message : String(err))}`);
      process.exitCode = 1;
      return;
    }

    const allPayloads: Awaited<ReturnType<typeof provider.generatePayloads>> = [];
    const payloadsByEndpoint = new Map<Endpoint, typeof allPayloads>();
    const addPayloads = (endpoint: Endpoint, payloads: typeof allPayloads) => {
      allPayloads.push(...payloads);
      const endpointPayloads = payloadsByEndpoint.get(endpoint) ?? [];
      endpointPayloads.push(...payloads);
      payloadsByEndpoint.set(endpoint, endpointPayloads);
    };
    let endpointsScanned = 0;
    let endpointsFailed = 0;

    // Step 2-3: Analyze and generate payloads per endpoint
    for (const endpoint of endpoints) {
      const endpointLabel = `${endpoint.method} ${sanitizeTerminalText(redactUrl(endpoint.url))}`;
      const analyzeSpinner = ora(`Analyzing ${endpointLabel}...`).start();
      const useFallbackPayloads = (vulns: Vulnerability[], message: string) => {
        const fallback = synthesizeFallbackPayloads(endpoint, vulns);
        console.warn(`${message}: ${fallback.length} payloads`);
        addPayloads(endpoint, fallback);
        endpointsScanned++;
      };
      try {
        const vulns = await provider.analyze(endpoint);
        analyzeSpinner.succeed(`Found ${vulns.length} potential vulnerabilities`);

        const payloadSpinner = ora("Generating attack payloads...").start();
        try {
          let payloads = await provider.generatePayloads(endpoint, vulns);
          if (payloads.length === 0) {
            // LLM returned zero - often happens with minimal body schemas.
            // Synthesize universal schema-independent probes so every scanned
            // endpoint gets the common auth-bypass / mass-assignment variants.
            const fallback = synthesizeFallbackPayloads(endpoint, vulns);
            payloadSpinner.warn(
              `LLM generated 0 payloads, using fallback generator: ${fallback.length} payloads`
            );
            payloads = fallback;
          } else {
            payloadSpinner.succeed(`Generated ${payloads.length} payloads`);
          }
          addPayloads(endpoint, payloads);
          endpointsScanned++;
        } catch (err) {
          payloadSpinner.fail(
            `Payload generation failed: ${sanitizeTerminalText(err instanceof Error ? err.message : String(err))}`
          );
          useFallbackPayloads(vulns, "Using fallback generator after payload generation failure");
          endpointsFailed++;
        }
      } catch (err) {
        analyzeSpinner.fail(
          `Analysis failed: ${sanitizeTerminalText(err instanceof Error ? err.message : String(err))}`
        );
        useFallbackPayloads([], "Using fallback generator after analysis failure");
        endpointsFailed++;
      }
    }

    if (allPayloads.length === 0) {
      if (endpointsFailed > 0) {
        console.error(`No payloads generated; ${endpointsFailed}/${endpoints.length} endpoint(s) failed.`);
        process.exitCode = 1;
      } else {
        console.log("No payloads generated. Exiting.");
      }
      return;
    }

    // Step 4: Dry run exits here
    if (opts.dryRun) {
      console.log(`\n${allPayloads.length} payloads generated (dry run):\n`);
      for (const p of allPayloads) {
        console.log(`  ${p.method} ${sanitizeTerminalText(redactUrl(p.url))} — ${sanitizeTerminalText(p.name)}`);
      }
      if (endpointsFailed > 0) {
        console.error(`\nAnalysis incomplete: ${endpointsFailed}/${endpoints.length} endpoint(s) failed.`);
        process.exitCode = 1;
      }
      return;
    }

    // Step 5: Execute payloads
    const execSpinner = ora("Firing payloads...").start();
    let resultIndex = 0;

    const results = [] as Awaited<ReturnType<typeof executePayloads>>;
    for (const endpoint of endpoints) {
      const endpointPayloads = payloadsByEndpoint.get(endpoint) ?? [];
      if (endpointPayloads.length === 0) continue;
      results.push(...await executePayloads(
        endpointPayloads,
        { concurrency, timeout, endpoint, allowPrivate: opts.allowPrivate },
        (result) => {
          resultIndex++;
          execSpinner.stop();
          logResult(result, resultIndex, allPayloads.length);
        }
      ));
    }

    // Step 6: Build findings from non-pass results
    const findings = buildFindings(results);
    const payloadsUnverified = results.filter((result) => result.classification === "unverified").length;
    if (payloadsUnverified > 0) process.exitCode = 1;
    if (reachesFailureThreshold(findings, failOn)) {
      process.exitCode = 1;
    }

    // Step 7-8: Score and build report
    const riskScore = calculateRiskScore(findings);
    const riskRating = getRiskRating(riskScore);
    const duration = Date.now() - startTime;

    const report: Report & { endpointsFailed?: number; payloadsUnverified?: number } = {
      target,
      timestamp: new Date().toISOString(),
      endpointsScanned,
      payloadsFired: allPayloads.length,
      findings,
      riskScore,
      riskRating,
      model,
      duration,
    };
    if (payloadsUnverified > 0) report.payloadsUnverified = payloadsUnverified;
    if (endpointsFailed > 0) {
      report.endpointsFailed = endpointsFailed;
      process.exitCode = 1;
    }

    // Step 9: Output reports
    logSummary(report);

    let mdPath: string | undefined;
    let jsonPath: string | undefined;
    let reportWriteFailed = false;

    try {
      mdPath = await writeMarkdownReport(report, outputDir);
    } catch (err) {
      console.error(`Markdown report failed: ${sanitizeTerminalText(err instanceof Error ? err.message : String(err))}`);
      reportWriteFailed = true;
    }

    try {
      jsonPath = await writeJSONReport(report, outputDir);
    } catch (err) {
      console.error(`JSON report failed: ${sanitizeTerminalText(err instanceof Error ? err.message : String(err))}`);
      reportWriteFailed = true;
    }

    console.log(`\nReport output:`);
    console.log(`  Markdown: ${mdPath ? sanitizeTerminalText(mdPath) : "FAILED"}`);
    console.log(`  JSON:     ${jsonPath ? sanitizeTerminalText(jsonPath) : "FAILED"}`);
    if (reportWriteFailed) {
      process.exitCode = 1;
    }
  });

await program.parseAsync();
