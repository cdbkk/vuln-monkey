import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import type { Report, Finding } from "../types.js";

function formatFinding(finding: Finding): string {
  const bodyStr = finding.payload.body !== undefined
    ? JSON.stringify(finding.payload.body, null, 2)
    : "N/A";

  const headersStr = Object.entries(finding.payload.headers)
    .map(([k, v]) => `${k}: ${v}`)
    .join("\n") || "None";

  return `### ${finding.title}

**Severity:** ${finding.severity}

${finding.description}

**Request**

| Field | Value |
|-------|-------|
| Method | \`${finding.payload.method}\` |
| URL | \`${finding.payload.url}\` |

Headers:
\`\`\`
${headersStr}
\`\`\`

Body:
\`\`\`json
${bodyStr}
\`\`\`

**Response**

| Field | Value |
|-------|-------|
| Status | \`${finding.response.statusCode}\` |
| Response Time | ${finding.response.responseTime}ms |

Body:
\`\`\`
${finding.response.body}
\`\`\`
`;
}

export async function writeMarkdownReport(report: Report, outputDir: string): Promise<string> {
  await mkdir(outputDir, { recursive: true });

  const timestamp = report.timestamp.replace(/:/g, "-");
  const filename = `vuln-monkey-${timestamp}.md`;
  const filePath = join(outputDir, filename);

  const durationSecs = (report.duration / 1000).toFixed(2);
  const date = new Date(report.timestamp).toUTCString();

  const findingsSection = report.findings.length > 0
    ? report.findings.map(formatFinding).join("\n---\n\n")
    : "_No findings._";

  const content = `# Vuln Monkey Report

## Metadata

| Field | Value |
|-------|-------|
| Target | ${report.target} |
| Model | ${report.model} |
| Date | ${date} |
| Duration | ${durationSecs}s |
| Risk Score | ${report.riskScore}/100 |
| Risk Rating | ${report.riskRating} |

## Findings

${findingsSection}

## Summary

| Metric | Value |
|--------|-------|
| Endpoints Scanned | ${report.endpointsScanned} |
| Payloads Fired | ${report.payloadsFired} |
| Findings | ${report.findings.length} |
`;

  await writeFile(filePath, content, "utf-8");
  return filePath;
}
