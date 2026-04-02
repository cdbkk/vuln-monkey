import { describe, it, expect } from "vitest";
import {
  parseVulnerabilities,
  parsePayloads,
  buildAnalysisPrompt,
} from "../../src/analyzer/prompts.js";
import type { Endpoint } from "../../src/types.js";

const TEST_ENDPOINT: Endpoint = {
  method: "POST",
  url: "https://api.example.com/users/123",
  headers: { "Content-Type": "application/json" },
  body: { name: "test" },
  auth: { type: "bearer", value: "token123" },
};

describe("parseVulnerabilities", () => {
  it("handles JSON wrapped in ```json fences", () => {
    const raw = `Here is my analysis:
\`\`\`json
[
  {
    "type": "IDOR",
    "description": "User can access other users resources",
    "severity": "high"
  }
]
\`\`\``;
    const vulns = parseVulnerabilities(raw, "https://api.example.com/users/123");
    expect(vulns).toHaveLength(1);
    expect(vulns[0].type).toBe("IDOR");
    expect(vulns[0].severity).toBe("high");
    expect(vulns[0].endpoint).toBe("https://api.example.com/users/123");
  });

  it("validates severity values", () => {
    const raw = `[
      { "type": "injection", "description": "SQL injection possible", "severity": "critical" },
      { "type": "IDOR", "description": "Missing auth check", "severity": "low" }
    ]`;
    const vulns = parseVulnerabilities(raw, "https://api.example.com");
    expect(vulns[0].severity).toBe("critical");
    expect(vulns[1].severity).toBe("low");
  });

  it("falls back to medium for unknown severity values", () => {
    const raw = `[
      { "type": "overflow", "description": "Buffer overflow", "severity": "extreme" },
      { "type": "race conditions", "description": "Race condition", "severity": "unknown" }
    ]`;
    const vulns = parseVulnerabilities(raw, "https://api.example.com");
    expect(vulns[0].severity).toBe("medium");
    expect(vulns[1].severity).toBe("medium");
  });

  it("returns empty array for unparseable input", () => {
    expect(parseVulnerabilities("not json at all", "https://api.example.com")).toEqual([]);
    expect(parseVulnerabilities("", "https://api.example.com")).toEqual([]);
    expect(parseVulnerabilities("{}", "https://api.example.com")).toEqual([]);
  });
});

describe("parsePayloads", () => {
  it("handles JSON wrapped in fences", () => {
    const raw = `\`\`\`json
[
  {
    "name": "IDOR - Access user 2",
    "vulnerability": "IDOR",
    "method": "GET",
    "url": "https://api.example.com/users/2",
    "headers": { "Authorization": "Bearer token" }
  }
]
\`\`\``;
    const payloads = parsePayloads(raw);
    expect(payloads).toHaveLength(1);
    expect(payloads[0].name).toBe("IDOR - Access user 2");
    expect(payloads[0].method).toBe("GET");
  });

  it("returns empty array for unparseable input", () => {
    expect(parsePayloads("not json")).toEqual([]);
    expect(parsePayloads("")).toEqual([]);
    expect(parsePayloads("{}")).toEqual([]);
  });
});

describe("buildAnalysisPrompt", () => {
  it("contains endpoint method and URL", () => {
    const prompt = buildAnalysisPrompt(TEST_ENDPOINT);
    expect(prompt).toContain("POST");
    expect(prompt).toContain("https://api.example.com/users/123");
  });

  it("mentions vulnerability types", () => {
    const prompt = buildAnalysisPrompt(TEST_ENDPOINT);
    expect(prompt).toContain("IDOR");
    expect(prompt).toContain("injection");
    expect(prompt).toContain("race conditions");
    expect(prompt).toContain("auth bypass");
  });
});
