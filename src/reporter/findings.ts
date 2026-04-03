import type { ExecutionResult, Finding } from "../types.js";

export function buildFindings(results: ExecutionResult[]): Finding[] {
  return results
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
}
