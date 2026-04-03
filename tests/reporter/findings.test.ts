import { describe, it, expect } from "vitest";
import { buildFindings } from "../../src/reporter/findings.js";
import type { ExecutionResult } from "../../src/types.js";

function makeResult(
  classification: ExecutionResult["classification"],
  overrides: Partial<ExecutionResult> = {}
): ExecutionResult {
  return {
    payload: {
      name: "test-payload",
      vulnerability: "test vulnerability",
      method: "GET",
      url: "https://api.example.com/test",
      headers: {},
    },
    statusCode: 200,
    responseTime: 100,
    responseBody: "response body",
    responseHeaders: {},
    classification,
    ...overrides,
  };
}

describe("buildFindings", () => {
  it("filters out pass results", () => {
    const results = [
      makeResult("pass"),
      makeResult("suspicious"),
      makeResult("crash"),
    ];
    const findings = buildFindings(results);
    expect(findings).toHaveLength(2);
  });

  it("maps crash to critical severity", () => {
    const results = [makeResult("crash")];
    const findings = buildFindings(results);
    expect(findings[0].severity).toBe("critical");
  });

  it("maps error to high severity", () => {
    const results = [makeResult("error")];
    const findings = buildFindings(results);
    expect(findings[0].severity).toBe("high");
  });

  it("maps suspicious to medium severity", () => {
    const results = [makeResult("suspicious")];
    const findings = buildFindings(results);
    expect(findings[0].severity).toBe("medium");
  });

  it("truncates response body to 500 chars", () => {
    const longBody = "x".repeat(1000);
    const results = [makeResult("error", { responseBody: longBody })];
    const findings = buildFindings(results);
    expect(findings[0].response.body).toHaveLength(500);
  });

  it("returns empty array when all pass", () => {
    const results = [makeResult("pass"), makeResult("pass"), makeResult("pass")];
    const findings = buildFindings(results);
    expect(findings).toHaveLength(0);
  });
});
