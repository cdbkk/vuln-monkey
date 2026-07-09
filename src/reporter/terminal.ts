import chalk from "chalk";
import type { ExecutionResult, Report, Finding, Severity } from "../types.js";

const ANSI_ESCAPE_RE = /\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1B\\))/g;
const C0_CONTROL_RE = /[\x00-\x1F\x7F]/g;

export function sanitizeTerminalText(value: string): string {
  return value.replace(ANSI_ESCAPE_RE, "").replace(C0_CONTROL_RE, "");
}

export function logResult(result: ExecutionResult, index: number, total: number): void {
  const { statusCode, responseTime, payload, classification } = result;
  const line = `[${index}/${total}] ${statusCode} ${responseTime}ms ${sanitizeTerminalText(payload.name)}`;

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

export function logSummary(report: Report & { endpointsFailed?: number }): void {
  const durationSecs = (report.duration / 1000).toFixed(2);

  console.log();
  console.log(chalk.bold("VULN MONKEY REPORT"));
  console.log(`Target:             ${sanitizeTerminalText(report.target)}`);
  console.log(`Model:              ${report.model}`);
  console.log(`Endpoints scanned:  ${report.endpointsScanned}`);
  if (report.endpointsFailed !== undefined && report.endpointsFailed > 0) {
    console.log(`Endpoints failed:   ${report.endpointsFailed}`);
  }
  console.log(`Payloads fired:     ${report.payloadsFired}`);
  console.log(`Duration:           ${durationSecs}s`);
  console.log(`Findings:           ${report.findings.length}`);

  const scoreStr = `Risk score: ${report.riskScore}/100`;
  if (report.riskScore > 70) {
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
      console.log(
        `${severityBadge(finding.severity)} ${sanitizeTerminalText(finding.title)} — ${sanitizeTerminalText(finding.endpoint)}`
      );
    }
  }
}
