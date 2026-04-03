#!/usr/bin/env node
import { Command } from "commander";
import { resolve } from "node:path";
import ora from "ora";
import { parseCurl } from "./parser/curl.js";
import { parseOpenAPIFromURL } from "./parser/openapi.js";
import { createProvider, VALID_MODELS } from "./analyzer/provider.js";
import { executePayloads } from "./executor/runner.js";
import { calculateRiskScore, getRiskRating } from "./reporter/score.js";
import { logResult, logSummary } from "./reporter/terminal.js";
import { writeMarkdownReport } from "./reporter/markdown.js";
import { writeJSONReport } from "./reporter/json.js";
import { buildFindings } from "./reporter/findings.js";
import type { Endpoint, Report } from "./types.js";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

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
  .option("--dry-run", "Generate payloads without firing", false)
  .action(async (curl, opts) => {
    if (!curl && !opts.spec) {
      program.error("Provide a curl command or --spec <url>");
    }

    if (!VALID_MODELS.has(opts.model)) {
      program.error(`Invalid model "${opts.model}". Must be one of: ${MODEL_LIST}`);
    }

    const concurrency = parseInt(opts.concurrency, 10);
    const timeout = parseInt(opts.timeout, 10);
    if (isNaN(concurrency) || concurrency < 1) {
      program.error("--concurrency must be a positive integer");
    }
    if (isNaN(timeout) || timeout < 1) {
      program.error("--timeout must be a positive integer");
    }

    const outputDir = resolve(opts.output);
    const SENSITIVE_DIRS = ["/etc", "/usr", "/bin", "/sbin", "/sys", "/proc", "/boot", "/root"];
    if (SENSITIVE_DIRS.some((d) => outputDir === d || outputDir.startsWith(d + "/"))) {
      program.error(`Output path "${outputDir}" targets a sensitive system directory`);
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
      parseSpinner.fail(`Parse failed: ${err instanceof Error ? err.message : err}`);
      process.exitCode = 1;
      return;
    }

    const target = opts.spec || endpoints[0]?.url || "unknown";
    const provider = createProvider(model);
    const allPayloads: Awaited<ReturnType<typeof provider.generatePayloads>> = [];
    let analysisFailures = 0;

    // Step 2-3: Analyze and generate payloads per endpoint
    for (const endpoint of endpoints) {
      const analyzeSpinner = ora(`Analyzing ${endpoint.method} ${endpoint.url}...`).start();
      try {
        const vulns = await provider.analyze(endpoint);
        analyzeSpinner.succeed(`Found ${vulns.length} potential vulnerabilities`);

        const payloadSpinner = ora("Generating attack payloads...").start();
        try {
          const payloads = await provider.generatePayloads(endpoint, vulns);
          payloadSpinner.succeed(`Generated ${payloads.length} payloads`);
          allPayloads.push(...payloads);
        } catch (err) {
          payloadSpinner.fail(`Payload generation failed: ${err instanceof Error ? err.message : err}`);
          analysisFailures++;
        }
      } catch (err) {
        analyzeSpinner.fail(`Analysis failed: ${err instanceof Error ? err.message : err}`);
        analysisFailures++;
      }
    }

    if (allPayloads.length === 0) {
      if (analysisFailures > 0) {
        console.error(`All ${analysisFailures} endpoint analysis(es) failed. Check your API key.`);
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
        console.log(`  ${p.method} ${p.url} — ${p.name}`);
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

    const report: Report = {
      target,
      timestamp: new Date().toISOString(),
      endpointsScanned: endpoints.length,
      payloadsFired: allPayloads.length,
      findings,
      riskScore,
      riskRating,
      model,
      duration,
    };

    // Step 9: Output reports
    logSummary(report);

    try {
      const mdPath = await writeMarkdownReport(report, outputDir);
      const jsonPath = await writeJSONReport(report, outputDir);
      console.log(`\nReports written:`);
      console.log(`  Markdown: ${mdPath}`);
      console.log(`  JSON:     ${jsonPath}`);
    } catch (err) {
      console.error(`Failed to write reports: ${err instanceof Error ? err.message : err}`);
      process.exitCode = 1;
    }
  });

await program.parseAsync();
