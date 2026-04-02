# Vuln Monkey AI Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build an npm-publishable API security fuzzer that uses LLMs to discover logic flaws in endpoints.

**Architecture:** CLI takes OpenAPI spec or curl command, normalizes to endpoint list, sends to LLM for vulnerability analysis, generates attack payloads, fires them with controlled concurrency, classifies results, and outputs terminal/markdown/JSON reports with a 0-100 risk score.

**Tech Stack:** TypeScript, Node.js, commander, chalk, ora, undici, zod, @anthropic-ai/sdk, @google/generative-ai, vitest

---

### Task 1: Project Scaffold

**Files:**
- Create: `package.json`
- Create: `tsconfig.json`
- Create: `src/types.ts`
- Create: `src/cli.ts`

**Step 1: Initialize project**

```bash
cd /Users/connor/Dev/vuln-monkey
npm init -y
```

**Step 2: Install dependencies**

```bash
npm install commander chalk ora undici zod @anthropic-ai/sdk @google/generative-ai
npm install -D typescript vitest @types/node tsx
```

**Step 3: Create tsconfig.json**

```json
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "ES2022",
    "moduleResolution": "bundler",
    "outDir": "dist",
    "rootDir": "src",
    "strict": true,
    "esModuleInterop": true,
    "skipLibCheck": true,
    "declaration": true,
    "resolveJsonModule": true,
    "forceConsistentCasingInFileNames": true
  },
  "include": ["src"],
  "exclude": ["node_modules", "dist", "tests"]
}
```

**Step 4: Create src/types.ts with all shared Zod schemas**

This is the single source of truth for all data shapes in the pipeline. Every module imports from here.

```typescript
import { z } from "zod";

export const EndpointSchema = z.object({
  method: z.enum(["GET", "POST", "PUT", "PATCH", "DELETE"]),
  url: z.string().url(),
  headers: z.record(z.string()).default({}),
  body: z.unknown().optional(),
  bodySchema: z.unknown().optional(),
  auth: z.object({
    type: z.enum(["bearer", "basic", "apikey", "none"]),
    value: z.string().optional(),
    headerName: z.string().optional(),
  }).default({ type: "none" }),
});
export type Endpoint = z.infer<typeof EndpointSchema>;

export const SeveritySchema = z.enum(["critical", "high", "medium", "low"]);
export type Severity = z.infer<typeof SeveritySchema>;

export const VulnerabilitySchema = z.object({
  type: z.string(),
  description: z.string(),
  severity: SeveritySchema,
  endpoint: z.string(),
});
export type Vulnerability = z.infer<typeof VulnerabilitySchema>;

export const AttackPayloadSchema = z.object({
  name: z.string(),
  vulnerability: z.string(),
  method: z.enum(["GET", "POST", "PUT", "PATCH", "DELETE"]),
  url: z.string(),
  headers: z.record(z.string()).default({}),
  body: z.unknown().optional(),
});
export type AttackPayload = z.infer<typeof AttackPayloadSchema>;

export const ResultClassification = z.enum([
  "pass",
  "suspicious",
  "error",
  "crash",
]);

export const ExecutionResultSchema = z.object({
  payload: AttackPayloadSchema,
  statusCode: z.number(),
  responseTime: z.number(),
  responseBody: z.string(),
  responseHeaders: z.record(z.string()),
  classification: ResultClassification,
  finding: z.string().optional(),
});
export type ExecutionResult = z.infer<typeof ExecutionResultSchema>;

export const FindingSchema = z.object({
  title: z.string(),
  severity: SeveritySchema,
  endpoint: z.string(),
  description: z.string(),
  payload: AttackPayloadSchema,
  response: z.object({
    statusCode: z.number(),
    body: z.string(),
    responseTime: z.number(),
  }),
});
export type Finding = z.infer<typeof FindingSchema>;

export const ReportSchema = z.object({
  target: z.string(),
  timestamp: z.string(),
  endpointsScanned: z.number(),
  payloadsFired: z.number(),
  findings: z.array(FindingSchema),
  riskScore: z.number().min(0).max(100),
  riskRating: z.enum(["Fail", "Needs Attention", "Acceptable"]),
  model: z.string(),
  duration: z.number(),
});
export type Report = z.infer<typeof ReportSchema>;

export interface LLMProvider {
  analyze(endpoint: Endpoint): Promise<Vulnerability[]>;
  generatePayloads(
    endpoint: Endpoint,
    vulnerabilities: Vulnerability[]
  ): Promise<AttackPayload[]>;
}

export interface CLIOptions {
  spec?: string;
  model: "claude" | "gemini";
  output: string;
  concurrency: number;
  timeout: number;
  dryRun: boolean;
}
```

**Step 5: Create minimal src/cli.ts**

```typescript
import { Command } from "commander";

const program = new Command();

program
  .name("vuln-monkey")
  .description("AI-powered API security fuzzer")
  .version("0.1.0")
  .argument("[curl]", "curl command to fuzz")
  .option("--spec <url>", "OpenAPI/Swagger spec URL")
  .option("--model <model>", "LLM backend: claude or gemini", "claude")
  .option("--output <dir>", "Report output directory", "./reports")
  .option("--concurrency <n>", "Parallel requests", "5")
  .option("--timeout <ms>", "Request timeout", "10000")
  .option("--dry-run", "Generate payloads without firing", false)
  .action(async (curl, opts) => {
    if (!curl && !opts.spec) {
      program.error("Provide a curl command or --spec <url>");
    }
    console.log("vuln-monkey starting...", { curl: !!curl, spec: opts.spec });
    // Pipeline wired in Task 8
  });

program.parse();
```

**Step 6: Add scripts to package.json**

Add to package.json:
```json
{
  "type": "module",
  "bin": { "vuln-monkey": "./dist/cli.js" },
  "scripts": {
    "dev": "tsx src/cli.ts",
    "build": "tsc",
    "test": "vitest run",
    "test:watch": "vitest"
  }
}
```

**Step 7: Verify it runs**

```bash
npx tsx src/cli.ts --help
```
Expected: Help output with all options listed.

**Step 8: Commit**

```bash
git init && git add -A && git commit -m "feat: project scaffold with types and CLI skeleton"
```

---

### Task 2: Curl Parser

**Files:**
- Create: `src/parser/curl.ts`
- Create: `tests/parser/curl.test.ts`

**Step 1: Write the failing tests**

```typescript
// tests/parser/curl.test.ts
import { describe, it, expect } from "vitest";
import { parseCurl } from "../../src/parser/curl.js";

describe("parseCurl", () => {
  it("parses a simple GET", () => {
    const result = parseCurl('curl https://api.example.com/users');
    expect(result.method).toBe("GET");
    expect(result.url).toBe("https://api.example.com/users");
    expect(result.headers).toEqual({});
    expect(result.body).toBeUndefined();
  });

  it("parses POST with headers and body", () => {
    const result = parseCurl(
      `curl -X POST https://api.example.com/users -H 'Content-Type: application/json' -H 'Authorization: Bearer tok123' -d '{"name":"test"}'`
    );
    expect(result.method).toBe("POST");
    expect(result.url).toBe("https://api.example.com/users");
    expect(result.headers["content-type"]).toBe("application/json");
    expect(result.headers["authorization"]).toBe("Bearer tok123");
    expect(result.body).toEqual({ name: "test" });
  });

  it("extracts bearer auth", () => {
    const result = parseCurl(
      `curl -H 'Authorization: Bearer mytoken' https://api.example.com/me`
    );
    expect(result.auth.type).toBe("bearer");
    expect(result.auth.value).toBe("mytoken");
  });

  it("handles double-quoted headers", () => {
    const result = parseCurl(
      `curl -H "Content-Type: application/json" https://api.example.com/test`
    );
    expect(result.headers["content-type"]).toBe("application/json");
  });

  it("handles --data flag", () => {
    const result = parseCurl(
      `curl -X PUT https://api.example.com/item/1 --data '{"price":99}'`
    );
    expect(result.method).toBe("PUT");
    expect(result.body).toEqual({ price: 99 });
  });

  it("throws on missing URL", () => {
    expect(() => parseCurl("curl -X POST")).toThrow();
  });
});
```

**Step 2: Run tests to verify they fail**

```bash
npx vitest run tests/parser/curl.test.ts
```
Expected: FAIL, module not found.

**Step 3: Implement curl parser**

```typescript
// src/parser/curl.ts
import type { Endpoint } from "../types.js";

export function parseCurl(command: string): Endpoint {
  const raw = command.replace(/^curl\s+/, "").trim();

  let method = "GET";
  const headers: Record<string, string> = {};
  let body: unknown | undefined;
  let url = "";

  // Tokenize respecting quotes
  const tokens: string[] = [];
  let current = "";
  let inQuote: string | null = null;

  for (const char of raw) {
    if (inQuote) {
      if (char === inQuote) {
        inQuote = null;
      } else {
        current += char;
      }
    } else if (char === "'" || char === '"') {
      inQuote = char;
    } else if (char === " ") {
      if (current) tokens.push(current);
      current = "";
    } else {
      current += char;
    }
  }
  if (current) tokens.push(current);

  let i = 0;
  while (i < tokens.length) {
    const token = tokens[i];

    if (token === "-X" || token === "--request") {
      method = tokens[++i].toUpperCase();
    } else if (token === "-H" || token === "--header") {
      const headerStr = tokens[++i];
      const colonIdx = headerStr.indexOf(":");
      if (colonIdx > 0) {
        const key = headerStr.slice(0, colonIdx).trim().toLowerCase();
        const val = headerStr.slice(colonIdx + 1).trim();
        headers[key] = val;
      }
    } else if (token === "-d" || token === "--data" || token === "--data-raw") {
      const dataStr = tokens[++i];
      try {
        body = JSON.parse(dataStr);
      } catch {
        body = dataStr;
      }
      if (method === "GET") method = "POST";
    } else if (token.startsWith("http://") || token.startsWith("https://")) {
      url = token;
    }

    i++;
  }

  if (!url) {
    throw new Error("No URL found in curl command");
  }

  // Detect auth
  const authHeader = headers["authorization"] || "";
  let auth: Endpoint["auth"] = { type: "none" };

  if (authHeader.toLowerCase().startsWith("bearer ")) {
    auth = { type: "bearer", value: authHeader.slice(7) };
  } else if (authHeader.toLowerCase().startsWith("basic ")) {
    auth = { type: "basic", value: authHeader.slice(6) };
  }

  return {
    method: method as Endpoint["method"],
    url,
    headers,
    body,
    auth,
  };
}
```

**Step 4: Run tests to verify they pass**

```bash
npx vitest run tests/parser/curl.test.ts
```
Expected: All 6 tests PASS.

**Step 5: Commit**

```bash
git add src/parser/curl.ts tests/parser/curl.test.ts
git commit -m "feat: curl parser with auth detection"
```

---

### Task 3: OpenAPI Parser

**Files:**
- Create: `src/parser/openapi.ts`
- Create: `tests/parser/openapi.test.ts`
- Create: `tests/fixtures/petstore.json`

**Step 1: Create test fixture**

Create `tests/fixtures/petstore.json` with a minimal OpenAPI 3.0 spec containing:
- 2 paths: `/users` (GET, POST) and `/users/{id}` (GET, DELETE)
- Server URL: `https://api.example.com`
- POST body schema with name and email properties

**Step 2: Write failing tests**

Test that the parser: extracts all 4 endpoints, sets correct methods, builds full URLs from server + path, and captures request body schema on the POST endpoint.

**Step 3: Implement OpenAPI parser**

Two exports:
- `parseOpenAPIFromJSON(spec)` for direct parsing
- `parseOpenAPIFromURL(url)` that fetches then parses

Iterate `spec.paths`, for each path iterate HTTP methods, extract body schema from `requestBody.content["application/json"].schema`, build full URL from `servers[0].url + path`.

**Step 4: Run tests, verify pass, commit**

```bash
git add src/parser/ tests/parser/ tests/fixtures/
git commit -m "feat: OpenAPI 3.x parser with URL and JSON input"
```

---

### Task 4: LLM Provider Abstraction + Prompts

**Files:**
- Create: `src/analyzer/provider.ts`
- Create: `src/analyzer/claude.ts`
- Create: `src/analyzer/gemini.ts`
- Create: `src/analyzer/prompts.ts`
- Create: `tests/analyzer/prompts.test.ts`

**Step 1: Create prompt templates**

`buildAnalysisPrompt(endpoint)`: Includes method, URL, auth type, body schema. Asks for exactly 5 vulnerabilities from a defined list (IDOR, type juggling, mass assignment, rate limiting bypass, auth bypass, injection, overflow, race conditions). Requests JSON array output.

`buildPayloadPrompt(endpoint, vulnerabilities)`: Takes endpoint + found vulns. Asks for 8 to 10 attack payloads per vulnerability as complete HTTP requests. JSON array output.

`parseVulnerabilities(raw, endpoint)`: Extracts JSON array from LLM response text (handles markdown code fences). Maps to Vulnerability type with severity validation.

`parsePayloads(raw)`: Same extraction logic for AttackPayload arrays.

**Step 2: Test the parse functions**

Test that `parseVulnerabilities` handles JSON wrapped in markdown fences, validates severity values, and falls back to "medium" for unknown severities. Test that `parsePayloads` handles the same.

**Step 3: Implement provider abstraction**

`createProvider(model)` factory that returns either `ClaudeProvider` or `GeminiProvider`. Both implement the `LLMProvider` interface from types.ts.

Claude uses `@anthropic-ai/sdk` with `claude-sonnet-4-6` model. Gemini uses `@google/generative-ai` with `gemini-2.5-flash`. Both call the prompt builders, send to API, parse response.

**Step 4: Run tests, verify pass, commit**

```bash
git add src/analyzer/ tests/analyzer/
git commit -m "feat: LLM provider abstraction with Claude and Gemini backends"
```

---

### Task 5: Payload Executor

**Files:**
- Create: `src/executor/runner.ts`
- Create: `tests/executor/runner.test.ts`

**Step 1: Write failing tests for classifyResponse**

Test cases:
- 2xx with attack payload = "suspicious"
- 5xx = "crash"
- 4xx with stack trace patterns (e.g., `at handler.js:42:15`) = "error"
- Clean 4xx (just `{"error":"Bad Request"}`) = "pass"
- 401/403 = "pass" (correctly rejected)

**Step 2: Implement classifyResponse and executePayloads**

`classifyResponse(statusCode, body, headers)`: Checks status ranges and scans body for stack trace patterns (JS, Python, Java, Go, SQL error patterns).

`executePayloads(payloads, options, onResult)`: Worker pool pattern. Spawns `concurrency` workers pulling from a shared queue. Each worker fires fetch with AbortController timeout, captures response, classifies it, calls onResult callback for live terminal output.

**Step 3: Run tests, verify pass, commit**

```bash
git add src/executor/ tests/executor/
git commit -m "feat: concurrent payload executor with response classification"
```

---

### Task 6: Risk Score Calculator

**Files:**
- Create: `src/reporter/score.ts`
- Create: `tests/reporter/score.test.ts`

**Step 1: Write failing tests**

Test: 0 findings = score 0. One critical = 25. Ten criticals caps at 100. Mixed severities add correctly (critical 25 + high 15 + low 2 = 42).

Test riskRating: above 70 = "Fail", 40 to 70 = "Needs Attention", below 40 = "Acceptable".

**Step 2: Implement**

Severity weights: critical=25, high=15, medium=5, low=2. Sum and cap at 100.

**Step 3: Run tests, verify pass, commit**

```bash
git add src/reporter/score.ts tests/reporter/score.test.ts
git commit -m "feat: risk score calculator with severity weights"
```

---

### Task 7: Reporter (Terminal + Markdown + JSON)

**Files:**
- Create: `src/reporter/terminal.ts`
- Create: `src/reporter/markdown.ts`
- Create: `src/reporter/json.ts`

**Step 1: Implement terminal reporter**

`logResult(result, index, total)`: Single line per payload result. Color coded by classification (green=pass, yellow=suspicious, red=error, bgRed=crash). Shows index/total, status code, response time, payload name.

`logSummary(report)`: Final summary block. Target, model, endpoints scanned, payloads fired, duration, finding count. Risk score with color background. Lists each finding with severity badge.

**Step 2: Implement markdown reporter**

`writeMarkdownReport(report, outputDir)`: Writes a `.md` file. Contains metadata table, findings list with request/response pairs, risk score. Footer links to GitHub repo.

**Step 3: Implement JSON reporter**

`writeJSONReport(report, outputDir)`: Writes the Report object as formatted JSON.

**Step 4: Commit**

```bash
git add src/reporter/
git commit -m "feat: terminal, markdown, and JSON reporters"
```

---

### Task 8: Wire the Pipeline in CLI

**Files:**
- Modify: `src/cli.ts`

**Step 1: Wire all modules into the CLI action**

The pipeline in order:
1. Parse input (curl or OpenAPI URL) into Endpoint[]
2. For each endpoint: call provider.analyze() to get Vulnerability[]
3. For each endpoint: call provider.generatePayloads() to get AttackPayload[]
4. If dry-run: print payloads and exit
5. Call executePayloads() with onResult callback for live terminal output
6. Filter results where classification != "pass" into Finding[]
7. Calculate risk score
8. Build Report object
9. Call logSummary(), writeMarkdownReport(), writeJSONReport()
10. Print file paths and exit

Use ora spinners for each phase. Handle errors at each step gracefully (log and continue to next endpoint).

**Step 2: Smoke test**

```bash
npx tsx src/cli.ts --help
npx tsx src/cli.ts --dry-run "curl -X POST https://httpbin.org/post -d '{\"test\":1}'"
```

**Step 3: Commit**

```bash
git add src/cli.ts
git commit -m "feat: wire full pipeline in CLI"
```

---

### Task 9: README

**Files:**
- Create: `README.md`

Write a README with: what it does (2 sentences), install (`npm install -g vuln-monkey`), usage examples (curl mode, openapi mode, dry run), options table, how the risk score works, screenshot placeholder, license MIT.

```bash
git add README.md
git commit -m "docs: README with usage and examples"
```

---

### Task 10: End-to-end smoke test

**Files:**
- Create: `tests/e2e/smoke.test.ts`

**Step 1: Write e2e smoke test**

Use vitest to spawn the CLI as a child process with `--help` flag and verify it outputs expected text. Use `--dry-run` mode with a curl command to verify the parse pipeline works without needing LLM keys. Use `execFileSync` (not `exec`) to avoid shell injection.

**Step 2: Run all tests**

```bash
npx vitest run
```

**Step 3: Commit**

```bash
git add tests/e2e/
git commit -m "test: CLI smoke tests"
```
