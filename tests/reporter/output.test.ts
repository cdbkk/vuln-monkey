import { describe, it, expect, afterEach } from "vitest";
import { writeJSONReport } from "../../src/reporter/json.js";
import { writeMarkdownReport } from "../../src/reporter/markdown.js";
import { readFile, rm } from "node:fs/promises";
import type { Report } from "../../src/types.js";

const TEST_REPORT: Report = {
  target: "https://api.example.com",
  timestamp: "2026-04-03T12:00:00.000Z",
  endpointsScanned: 2,
  payloadsFired: 10,
  findings: [],
  riskScore: 0,
  riskRating: "Acceptable",
  model: "claude",
  duration: 5000,
};

const TEST_DIR = "/tmp/vuln-monkey-test-output";

const SECRET_REPORT: Report = {
  ...TEST_REPORT,
  target: "https://user:pass@api.example.com?token=query-secret",
  findings: [{
    title: "secret test",
    severity: "high",
    endpoint: "https://api.example.com/login?api_key=query-secret",
    description: "response included a credential",
    payload: {
      name: "login",
      vulnerability: "auth bypass",
      method: "POST",
      url: "https://api.example.com/login?token=query-secret",
      headers: {
        Authorization: "Bearer header-secret",
        "X-Custom-Key": "custom-header-secret",
      },
      body: { password: "body-secret" },
    },
    response: {
      statusCode: 200,
      body: JSON.stringify({ access_token: "response-secret" }),
      responseTime: 12,
    },
  }],
};

afterEach(async () => {
  await rm(TEST_DIR, { recursive: true, force: true });
});

describe("writeJSONReport", () => {
  it("creates valid JSON file", async () => {
    const filePath = await writeJSONReport(TEST_REPORT, TEST_DIR);
    const raw = await readFile(filePath, "utf-8");
    const parsed = JSON.parse(raw);
    expect(parsed.target).toBe("https://api.example.com");
  });

  it("returns path ending in .json", async () => {
    const filePath = await writeJSONReport(TEST_REPORT, TEST_DIR);
    expect(filePath.endsWith(".json")).toBe(true);
  });

  it("redacts secrets from JSON output", async () => {
    const filePath = await writeJSONReport(SECRET_REPORT, TEST_DIR);
    const content = await readFile(filePath, "utf-8");
    for (const secret of ["pass@api", "query-secret", "header-secret", "custom-header-secret", "body-secret", "response-secret"]) {
      expect(content).not.toContain(secret);
    }
    expect(content).toContain("[REDACTED]");
  });
});

describe("writeMarkdownReport", () => {
  it("creates markdown file", async () => {
    const filePath = await writeMarkdownReport(TEST_REPORT, TEST_DIR);
    const content = await readFile(filePath, "utf-8");
    expect(content).toContain("# Vuln Monkey Report");
    expect(content).toContain("Acceptable");
  });

  it("returns path ending in .md", async () => {
    const filePath = await writeMarkdownReport(TEST_REPORT, TEST_DIR);
    expect(filePath.endsWith(".md")).toBe(true);
  });

  it("redacts secrets from Markdown output", async () => {
    const filePath = await writeMarkdownReport(SECRET_REPORT, TEST_DIR);
    const content = await readFile(filePath, "utf-8");
    for (const secret of ["pass@api", "query-secret", "header-secret", "custom-header-secret", "body-secret", "response-secret"]) {
      expect(content).not.toContain(secret);
    }
    expect(content).toContain("[REDACTED]");
  });
});
