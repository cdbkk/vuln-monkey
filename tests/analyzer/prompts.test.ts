import { describe, it, expect } from "vitest";
import {
  parseVulnerabilities,
  parsePayloads,
  buildAnalysisPrompt,
  buildPayloadPrompt,
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

  it("caps model output at five vulnerabilities", () => {
    const raw = JSON.stringify(Array.from({ length: 20 }, (_, index) => ({
      type: `type-${index}`,
      description: "test",
      severity: "low",
    })));
    expect(parseVulnerabilities(raw, "https://api.example.com")).toHaveLength(5);
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

  it("preserves execution expectations from validated model output", () => {
    const payloads = parsePayloads(JSON.stringify([{
      name: "No credentials",
      vulnerability: "auth bypass",
      method: "GET",
      url: "https://api.example.com/users",
      headers: {},
      omitAuth: true,
      expectRejection: true,
    }]));

    expect(payloads[0]).toMatchObject({ omitAuth: true, expectRejection: true });
  });

  it("returns empty array for unparseable input", () => {
    expect(parsePayloads("not json")).toEqual([]);
    expect(parsePayloads("")).toEqual([]);
    expect(parsePayloads("{}")).toEqual([]);
  });

  it("caps model output at fifty payloads", () => {
    const raw = JSON.stringify(Array.from({ length: 100 }, (_, index) => ({
      name: `payload-${index}`,
      vulnerability: "test",
      method: "GET",
      url: "https://api.example.com",
      headers: {},
    })));
    expect(parsePayloads(raw)).toHaveLength(50);
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

  it("does not send credentials to model providers", () => {
    const endpoint: Endpoint = {
      ...TEST_ENDPOINT,
      url: "https://user:pass@api.example.com/users?access_token=query-secret",
      headers: {
        Authorization: "Bearer header-secret",
        Cookie: "session=cookie-secret",
        "X-Custom-Key": "custom-header-secret",
      },
      body: { username: "connor", password: "body-secret" },
      bodySchema: { example: { apiKey: "schema-secret" } },
      auth: { type: "apikey", headerName: "X-Custom-Key", value: "custom-header-secret" },
    };

    const prompts = [
      buildAnalysisPrompt(endpoint),
      buildPayloadPrompt(endpoint, []),
    ];

    for (const prompt of prompts) {
      expect(prompt).not.toContain("pass@api");
      expect(prompt).not.toContain("query-secret");
      expect(prompt).not.toContain("header-secret");
      expect(prompt).not.toContain("cookie-secret");
      expect(prompt).not.toContain("custom-header-secret");
      expect(prompt).not.toContain("body-secret");
      expect(prompt).not.toContain("schema-secret");
      expect(prompt).toContain("[REDACTED]");
    }
  });
});
