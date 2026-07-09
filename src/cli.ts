#!/usr/bin/env node
import { Command } from "commander";
import { resolve } from "node:path";
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
import type { Endpoint, Report, Vulnerability } from "./types.js";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const __dirname = dirname(fileURLToPath(import.meta.url));
const pkg = JSON.parse(readFileSync(join(__dirname, "..", "package.json"), "utf-8"));
const MODEL_LIST = [...VALID_MODELS].join(", ");

const program = new Command();

function parsePositiveIntegerOption(value: string, option: string): number {
  if (!/^[1-9]\d*$/.test(value)) {
    program.error(`${option} must be a positive integer (received "${sanitizeTerminalText(value)}")`);
  }
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed)) {
    program.error(`${option} must be a safe positive integer (received "${sanitizeTerminalText(value)}")`);
  }
  return parsed;
}

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
  .option("--dry-run", "Generate payloads without firing", false)
  .action(async (curl, opts) => {
    if (!curl && !opts.spec) {
      program.error("Provide a curl command or --spec <url>");
    }

    if (!VALID_MODELS.has(opts.model)) {
      program.error(`Invalid model "${sanitizeTerminalText(opts.model)}". Must be one of: ${MODEL_LIST}`);
    }

    const concurrency = parsePositiveIntegerOption(opts.concurrency, "--concurrency");
    const timeout = parsePositiveIntegerOption(opts.timeout, "--timeout");

    const outputDir = resolve(opts.output);
    const SENSITIVE_DIRS = ["/etc", "/usr", "/bin", "/sbin", "/sys", "/proc", "/boot", "/root"];
    if (SENSITIVE_DIRS.some((d) => outputDir === d || outputDir.startsWith(d + "/"))) {
      program.error(`Output path "${sanitizeTerminalText(outputDir)}" targets a sensitive system directory`);
    }

    const startTime = Date.now();
    const model = opts.model;

    // Step 1: Parse input into endpoints
    const parseSpinner = ora("Parsing input...").start();
    let endpoints: Endpoint[];

    try {
      if (opts.spec) {
        endpoints = await parseOpenAPIFromURL(opts.spec);
      } else {
        endpoints = [parseCurl(curl)];
      }
      if (endpoints.length === 0) {
        parseSpinner.fail("No endpoints found in spec");
        process.exitCode = 1;
        return;
      }
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
    let endpointsScanned = 0;
    let endpointsFailed = 0;

    // Step 2-3: Analyze and generate payloads per endpoint
    for (const endpoint of endpoints) {
      const endpointLabel = `${endpoint.method} ${sanitizeTerminalText(endpoint.url)}`;
      const analyzeSpinner = ora(`Analyzing ${endpointLabel}...`).start();
      const useFallbackPayloads = (vulns: Vulnerability[], message: string) => {
        const fallback = synthesizeFallbackPayloads(endpoint, vulns);
        console.warn(`${message}: ${fallback.length} payloads`);
        allPayloads.push(...fallback);
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
          allPayloads.push(...payloads);
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
        console.log(`  ${p.method} ${sanitizeTerminalText(p.url)} — ${sanitizeTerminalText(p.name)}`);
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

    const results = await executePayloads(
      allPayloads,
      { concurrency, timeout },
      (result) => {
        resultIndex++;
        execSpinner.stop();
        logResult(result, resultIndex, allPayloads.length);
      }
    );

    // Step 6: Build findings from non-pass results
    const findings = buildFindings(results);

    // Step 7-8: Score and build report
    const riskScore = calculateRiskScore(findings);
    const riskRating = getRiskRating(riskScore);
    const duration = Date.now() - startTime;

    const report: Report & { endpointsFailed?: number } = {
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
