import type { ExecutionResult, Finding } from "../types.js";

const MAX_BODY_LENGTH = 500;

function severityForResult(result: ExecutionResult): Finding["severity"] {
  if (result.statusCode === 0) return "low";
  if (result.classification === "suspicious") return "high";
  if (result.classification === "crash") return "medium";
  if (result.classification === "error") return "high";
  return "low";
}

export function buildFindings(results: ExecutionResult[]): Finding[] {
  return results
    .filter((r) => r.classification !== "pass")
    .map((r) => ({
      title: `${r.classification.toUpperCase()}: ${r.payload.name}`,
      severity: severityForResult(r),
      endpoint: r.payload.url,
      description: r.payload.vulnerability,
      payload: r.payload,
      response: {
        statusCode: r.statusCode,
        body: r.responseBody.slice(0, MAX_BODY_LENGTH),
        responseTime: r.responseTime,
      },
    }));
}
