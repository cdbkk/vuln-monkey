import { Command } from "commander";
import ora from "ora";
import { parseCurl } from "./parser/curl.js";
import { parseOpenAPIFromURL } from "./parser/openapi.js";
import { createProvider } from "./analyzer/provider.js";
import { executePayloads } from "./executor/runner.js";
import { calculateRiskScore, getRiskRating } from "./reporter/score.js";
import { logResult, logSummary } from "./reporter/terminal.js";
import { writeMarkdownReport } from "./reporter/markdown.js";
import { writeJSONReport } from "./reporter/json.js";
import type { Endpoint, Finding, Report } from "./types.js";

const program = new Command();

program
  .name("vuln-monkey")
  .description("AI-powered API security fuzzer")
  .version("0.1.0")
  .argument("[curl]", "curl command to fuzz")
  .option("--spec <url>", "OpenAPI/Swagger spec URL")
  .option("--model <model>", "LLM backend: claude or gemini", "claude")
  .option("--output <dir>", "Report output directory", "./reports")
  .option("--concurrency <n>", "Parallel requests", "5")
  .option("--timeout <ms>", "Request timeout", "10000")
  .option("--dry-run", "Generate payloads without firing", false)
  .action(async (curl, opts) => {
    if (!curl && !opts.spec) {
      program.error("Provide a curl command or --spec <url>");
    }

    const startTime = Date.now();
    const model = opts.model as "claude" | "gemini";
    const concurrency = parseInt(opts.concurrency, 10);
    const timeout = parseInt(opts.timeout, 10);

    // Step 1: Parse input into endpoints
    const parseSpinner = ora("Parsing input...").start();
    let endpoints: Endpoint[];

    try {
      if (opts.spec) {
        endpoints = await parseOpenAPIFromURL(opts.spec);
      } else {
        endpoints = [parseCurl(curl)];
      }
      parseSpinner.succeed(`Parsed ${endpoints.length} endpoint(s)`);
    } catch (err) {
      parseSpinner.fail(`Parse failed: ${err instanceof Error ? err.message : err}`);
      process.exit(1);
    }

    const target = opts.spec || endpoints[0]?.url || "unknown";
    const provider = createProvider(model);
    const allPayloads: Awaited<ReturnType<typeof provider.generatePayloads>> = [];

    // Step 2-3: Analyze and generate payloads per endpoint
    for (const endpoint of endpoints) {
      const analyzeSpinner = ora(`Analyzing ${endpoint.method} ${endpoint.url}...`).start();
      try {
        const vulns = await provider.analyze(endpoint);
        analyzeSpinner.succeed(`Found ${vulns.length} potential vulnerabilities`);

        const payloadSpinner = ora("Generating attack payloads...").start();
        const payloads = await provider.generatePayloads(endpoint, vulns);
        payloadSpinner.succeed(`Generated ${payloads.length} payloads`);
        allPayloads.push(...payloads);
      } catch (err) {
        analyzeSpinner.fail(`Analysis failed: ${err instanceof Error ? err.message : err}`);
      }
    }

    if (allPayloads.length === 0) {
      console.log("No payloads generated. Exiting.");
      process.exit(0);
    }

    // Step 4: Dry run exits here
    if (opts.dryRun) {
      console.log(`\n${allPayloads.length} payloads generated (dry run):\n`);
      for (const p of allPayloads) {
        console.log(`  ${p.method} ${p.url} — ${p.name}`);
      }
      process.exit(0);
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
    const findings: Finding[] = results
      .filter((r) => r.classification !== "pass")
      .map((r) => ({
        title: `${r.classification.toUpperCase()}: ${r.payload.name}`,
        severity: r.classification === "crash" ? "critical" as const
          : r.classification === "error" ? "high" as const
          : "medium" as const,
        endpoint: r.payload.url,
        description: r.payload.vulnerability,
        payload: r.payload,
        response: {
          statusCode: r.statusCode,
          body: r.responseBody.slice(0, 500),
          responseTime: r.responseTime,
        },
      }));

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

    const mdPath = await writeMarkdownReport(report, opts.output);
    const jsonPath = await writeJSONReport(report, opts.output);

    console.log(`\nReports written:`);
    console.log(`  Markdown: ${mdPath}`);
    console.log(`  JSON:     ${jsonPath}`);
  });

program.parse();
