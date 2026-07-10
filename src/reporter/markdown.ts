import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import type { Report, Finding } from "../types.js";
import { redactValue } from "../security/redaction.js";
import { generateReportFilename } from "./filename.js";

const SENSITIVE_HEADERS = new Set(["authorization", "cookie", "x-api-key", "x-auth-token"]);
const STRUCTURAL_START_RE = /^(\s*)([#>*+\-=]|\d+[.)])/;

function redactHeader(key: string, value: string): string {
  if (SENSITIVE_HEADERS.has(key.toLowerCase())) {
    return "[REDACTED]";
  }
  return value;
}

function escapeMarkdownText(value: string): string {
  return value
    .replace(/\\/g, "\\\\")
    .replace(/`/g, "\\`")
    .replace(/\|/g, "\\|")
    .replace(/\r\n?/g, "\n")
    .replace(/\n/g, "\\n")
    .replace(STRUCTURAL_START_RE, "$1\\$2");
}

function markdownCodeSpan(value: string): string {
  const text = value
    .replace(/\r\n?/g, "\n")
    .replace(/\n/g, "\\n")
    .replace(/\|/g, "\\|");
  const maxTicks = Math.max(0, ...Array.from(text.matchAll(/`+/g), (match) => match[0].length));
  const ticks = "`".repeat(maxTicks + 1);
  const padding = text.startsWith("`") || text.endsWith("`") || text.startsWith(" ") || text.endsWith(" ")
    ? " "
    : "";
  return `${ticks}${padding}${text}${padding}${ticks}`;
}

function escapeFence(value: string): string {
  return value.replace(/```/g, "\\`\\`\\`");
}

function formatFinding(finding: Finding): string {
  const bodyStr = finding.payload.body !== undefined
    ? JSON.stringify(finding.payload.body, null, 2)
    : "N/A";

  const headersStr = Object.entries(finding.payload.headers)
    .map(([k, v]) => `${escapeFence(k)}: ${escapeFence(redactHeader(k, v))}`)
    .join("\n") || "None";

  return `### ${escapeMarkdownText(finding.title)}

**Severity:** ${finding.severity}

${escapeMarkdownText(finding.description)}

**Request**

| Field | Value |
|-------|-------|
| Method | ${markdownCodeSpan(finding.payload.method)} |
| URL | ${markdownCodeSpan(finding.payload.url)} |

Headers:
\`\`\`
${headersStr}
\`\`\`

Body:
\`\`\`json
${escapeFence(bodyStr)}
\`\`\`

**Response**

| Field | Value |
|-------|-------|
| Status | \`${finding.response.statusCode}\` |
| Response Time | ${finding.response.responseTime}ms |

Body:
\`\`\`
${escapeFence(finding.response.body)}
\`\`\`
`;
}

export async function writeMarkdownReport(report: Report, outputDir: string): Promise<string> {
  await mkdir(outputDir, { recursive: true });

  const safeReport = redactValue(report) as Report;

  const filename = generateReportFilename(safeReport.timestamp, "md");
  const filePath = join(outputDir, filename);

  const durationSecs = (safeReport.duration / 1000).toFixed(2);
  const date = new Date(safeReport.timestamp).toUTCString();

  const findingsSection = safeReport.findings.length > 0
    ? safeReport.findings.map(formatFinding).join("\n---\n\n")
    : "_No findings._";
  const failedEndpoints = "endpointsFailed" in safeReport && typeof safeReport.endpointsFailed === "number"
    ? safeReport.endpointsFailed
    : 0;
  const failedEndpointsRow = failedEndpoints > 0
    ? `| Endpoints Failed | ${failedEndpoints} |\n`
    : "";
  const unverifiedPayloadsRow = safeReport.payloadsUnverified
    ? `| Payloads Unverified | ${safeReport.payloadsUnverified} |\n`
    : "";

  const content = `# Vuln Monkey Report

## Metadata

| Field | Value |
|-------|-------|
| Target | ${escapeMarkdownText(safeReport.target)} |
| Model | ${safeReport.model} |
| Date | ${date} |
| Duration | ${durationSecs}s |
| Risk Score | ${safeReport.riskScore}/100 |
| Risk Rating | ${safeReport.riskRating} |

## Findings

${findingsSection}

## Summary

| Metric | Value |
|--------|-------|
| Endpoints Scanned | ${safeReport.endpointsScanned} |
${failedEndpointsRow}| Payloads Fired | ${safeReport.payloadsFired} |
${unverifiedPayloadsRow}| Findings | ${safeReport.findings.length} |
`;

  await writeFile(filePath, content, "utf-8");
  return filePath;
}
