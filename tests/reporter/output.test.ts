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
});
