import chalk from "chalk";
import type { ExecutionResult, Report, Finding, Severity } from "../types.js";

export function logResult(result: ExecutionResult, index: number, total: number): void {
  const { statusCode, responseTime, payload, classification } = result;
  const line = `[${index}/${total}] ${statusCode} ${responseTime}ms ${payload.name}`;

  switch (classification) {
    case "pass":
      console.log(chalk.green(line));
      break;
    case "suspicious":
      console.log(chalk.yellow(line));
      break;
    case "error":
      console.log(chalk.red(line));
      break;
    case "crash":
      console.log(chalk.bgRed(line));
      break;
  }
}

function severityBadge(severity: Severity): string {
  switch (severity) {
    case "critical":
      return chalk.bgRed.white(" CRITICAL ");
    case "high":
      return chalk.red(" HIGH ");
    case "medium":
      return chalk.yellow(" MEDIUM ");
    case "low":
      return chalk.blue(" LOW ");
  }
}

export function logSummary(report: Report): void {
  const durationSecs = (report.duration / 1000).toFixed(2);

  console.log();
  console.log(chalk.bold("VULN MONKEY REPORT"));
  console.log(`Target:             ${report.target}`);
  console.log(`Model:              ${report.model}`);
  console.log(`Endpoints scanned:  ${report.endpointsScanned}`);
  console.log(`Payloads fired:     ${report.payloadsFired}`);
  console.log(`Duration:           ${durationSecs}s`);
  console.log(`Findings:           ${report.findings.length}`);

  const scoreStr = `Risk score: ${report.riskScore}/100`;
  if (report.riskScore >= 70) {
    console.log(chalk.bgRed.white(scoreStr));
  } else if (report.riskScore >= 40) {
    console.log(chalk.yellow(scoreStr));
  } else {
    console.log(chalk.green(scoreStr));
  }

  console.log(`Risk rating:        ${report.riskRating}`);

  if (report.findings.length > 0) {
    console.log();
    for (const finding of report.findings) {
      console.log(`${severityBadge(finding.severity)} ${finding.title} — ${finding.endpoint}`);
    }
  }
}
