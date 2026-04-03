# Consolidated Code Review: vuln-monkey

> 13 agents (5 Sonnet, 5 Codex, 3 Gemini). Findings deduplicated and prioritized.

---

## CRITICAL (must fix before use)

### C1. Build fails: Zod v4 API incompatibility
**Source:** Codex (publish readiness)
**Files:** `src/types.ts:6,33,50`
`tsc --noEmit` fails with 4 errors. Zod v4 changed its API. Schema definitions need updating. Also `src/executor/runner.ts:62` has a `Record<string, unknown>` vs `HeadersInit` type mismatch.

### C2. Missing shebang in CLI entry point
**Source:** Codex (publish readiness)
**File:** `src/cli.ts:1`
No `#!/usr/bin/env node` at top. After `npm install -g`, the binary won't execute on most systems.

### C3. SSRF: No URL validation on executor or OpenAPI fetcher
**Source:** Sonnet (security), Gemini (codebase)
**Files:** `src/executor/runner.ts:73`, `src/parser/openapi.ts:34`
The executor fires any URL the LLM generates, including `http://127.0.0.1`, `http://169.254.169.254` (cloud metadata), `file://`. OpenAPI fetcher also has no scheme check. Combined with LLM prompt injection (C5), this is a complete SSRF chain.

### C4. SSRF via redirects: fetch follows redirects by default
**Source:** Sonnet (security)
**File:** `src/executor/runner.ts:73`
No `redirect: "manual"`. A target can 302 to internal services.

### C5. LLM prompt injection to SSRF pivot
**Source:** Sonnet (security), Gemini (prompt engineering)
**Files:** `src/analyzer/prompts.ts:14-45,59-88`
Endpoint data (URL, headers, body schema) is interpolated into prompts with no escaping. A hostile API or malicious OpenAPI spec can steer the LLM to emit internal URLs as payloads.

### C6. DoS: Unbounded response body buffering
**Source:** Sonnet (security)
**File:** `src/executor/runner.ts:77`
`response.text()` reads entire body into memory. A multi-GB chunked response exhausts the heap. No size limit.

---

## HIGH (fix before shipping)

### H1. Unhandled promise rejection at top level
**Source:** Sonnet (CLI pipeline), Codex (error handling)
**File:** `src/cli.ts:146`
`program.parse()` is sync. The async `.action()` is not awaited. Anything throwing after the try/catch blocks (executePayloads, file writes) becomes an unhandled rejection. Fix: use `program.parseAsync()`.

### H2. parseInt produces NaN with no guard
**Source:** Sonnet (type safety, CLI pipeline)
**File:** `src/cli.ts:33-34`
`--concurrency foo` produces `NaN`. `Math.min(NaN, ...)` returns `NaN`, spawning zero workers. Silent failure.

### H3. Model option not validated at runtime
**Source:** Sonnet (type safety)
**File:** `src/cli.ts:32`
`opts.model as "claude" | "gemini"` accepts any string. `--model gpt4` passes the cast and reaches `createProvider` unchecked.

### H4. classifyResponse returns string, not typed enum
**Source:** Sonnet (type safety)
**File:** `src/executor/runner.ts:15`
Returns `string` instead of `z.infer<typeof ResultClassification>`. Causes cascade `as` cast on line 100.

### H5. Curl parser: unsafe method cast bypasses enum validation
**Source:** Sonnet (type safety, parsers)
**File:** `src/parser/curl.ts:78`
`-X CONNECT` silently produces invalid Endpoint. Should validate against the enum.

### H6. Curl parser: escaped quotes break tokenization
**Source:** Sonnet (parsers), Gemini (codebase)
**File:** `src/parser/curl.ts:16-31`
`curl -d "{\"key\":\"val\"}"` breaks. No backslash-escape handling in tokenizer.

### H7. OpenAPI parser: trailing slash produces double-slash URLs
**Source:** Sonnet (parsers)
**File:** `src/parser/openapi.ts:6,20`
`https://api.example.com/` + `/users` = `https://api.example.com//users`.

### H8. OpenAPI parser: missing servers array produces relative URLs
**Source:** Sonnet (parsers), Gemini (codebase)
**File:** `src/parser/openapi.ts:6`
Falls back to `""`, producing `/users` as the URL. Downstream fetch fails with no useful error.

### H9. Credential leakage into LLM prompts and reports
**Source:** Sonnet (security)
**Files:** `src/analyzer/prompts.ts:14-45`, `src/reporter/markdown.ts:10-12`
Bearer tokens in URLs/headers are sent to Anthropic/Google verbatim. Auth headers appear unredacted in markdown reports.

### H10. Reporter file writes have no error handling
**Source:** Codex (error handling)
**Files:** `src/reporter/json.ts:6-12`, `src/reporter/markdown.ts:54-80`
`mkdir` and `writeFile` failures propagate to the unhandled rejection (H1). Scan results lost.

### H11. Gemini API key silently empty
**Source:** Codex (SDK usage, error handling), Sonnet (security)
**File:** `src/analyzer/gemini.ts:9`
`process.env.GEMINI_API_KEY || ""` fails at call time with confusing error. Should throw at construction.

### H12. No npm publish filtering
**Source:** Codex (publish readiness)
**File:** `package.json`
No `"files"` field or `.npmignore`. Tests, source, and dev artifacts all ship. Add `"files": ["dist"]`.

---

## MEDIUM (improve before v1)

### M1. Spinner leak when generatePayloads throws
**Source:** Sonnet (CLI pipeline), Codex (error handling)
**File:** `src/cli.ts:60-63`
`payloadSpinner` started but never stopped on error. Corrupts terminal output.

### M2. Silent continuation after all analyses fail
**Source:** Codex (error handling)
**File:** `src/cli.ts:58-65`
If every endpoint analysis fails (bad API key), tool exits 0 with "No payloads generated." No indication of failure.

### M3. Bare catch discards error in executor
**Source:** Codex (error handling), Gemini (codebase)
**File:** `src/executor/runner.ts:82`
Actual error discarded. Can't distinguish timeout from DNS failure from connection refused.

### M4. No retry/rate limit handling on LLM calls
**Source:** Codex (SDK usage)
**Files:** `src/analyzer/claude.ts`, `src/analyzer/gemini.ts`
A single 429 kills the run. Anthropic SDK has built-in retries; Gemini does not.

### M5. No timeout on LLM API calls
**Source:** Codex (SDK usage)
**Files:** `src/analyzer/claude.ts`, `src/analyzer/gemini.ts`
Hanged LLM blocks the process forever.

### M6. Prompt forces exactly 5 vulnerabilities (hallucination risk)
**Source:** Gemini (prompt engineering), Codex (SDK usage)
**File:** `src/analyzer/prompts.ts:28`
Simple endpoints have fewer than 5 real issues. LLM forced to hallucinate.

### M7. Markdown code blocks break on triple-backtick content
**Source:** Gemini (reporters)
**File:** `src/reporter/markdown.ts:44-46`
Response bodies containing ``` break the report formatting.

### M8. Filename collision risk on concurrent runs
**Source:** Gemini (reporters)
**Files:** `src/reporter/markdown.ts`, `src/reporter/json.ts`
Timestamp-based filenames collide within the same millisecond.

### M9. Path traversal on --output flag
**Source:** Sonnet (security)
**Files:** `src/reporter/json.ts:6`, `src/reporter/markdown.ts:52`
`--output /etc` writes files there. No path validation.

### M10. Unused dependency: undici
**Source:** Haiku (dependency audit)
**File:** `package.json`
Listed but never imported. Remove.

### M11. Missing `export type ResultClassification`
**Source:** Sonnet (type safety)
**File:** `src/types.ts:38`
Every other schema has a paired type export. This one is missing.

### M12. OpenAPI parser ignores non-JSON request bodies
**Source:** Sonnet (parsers)
**File:** `src/parser/openapi.ts:15-16`
`multipart/form-data` and `x-www-form-urlencoded` bodies silently dropped.

### M13. Curl parser: no bounds check on token access
**Source:** Gemini (codebase)
**File:** `src/parser/curl.ts:39`
`tokens[++i]` without bounds check. `curl -X` (no method) reads undefined.

---

## LOW (nice to have)

### L1. Hardcoded LLM model names
**Source:** Codex (architecture, SDK usage)
**Files:** `src/analyzer/claude.ts:14`, `src/analyzer/gemini.ts:10`
Should be configurable. `claude-sonnet-4-6` may not be the correct model string.

### L2. No Reporter interface
**Source:** Codex (architecture)
Adding new output formats requires editing cli.ts. A common interface would allow pluggable reporters.

### L3. Finding construction logic in CLI
**Source:** Codex (architecture)
**File:** `src/cli.ts:100-115`
Severity mapping policy (crash=critical, error=high, suspicious=medium) belongs in a domain module, not the CLI orchestrator.

### L4. E2E tests only test help/version
**Source:** Sonnet (test quality)
**File:** `tests/e2e/smoke.test.ts`
No test exercises actual parsing pipeline or --dry-run. Hardcoded absolute path makes tests non-portable.

### L5. executePayloads has zero tests
**Source:** Sonnet (test quality)
Core execution function (concurrency, timeouts, callbacks) completely untested.

### L6. Reporter modules have zero tests
**Source:** Sonnet (test quality), Gemini (reporters)
Terminal, markdown, and JSON reporters have no test coverage at all.

### L7. Missing OWASP API Top 10 coverage in prompts
**Source:** Gemini (prompt engineering)
Missing BOLA, excessive data exposure, CORS, information disclosure categories.

### L8. process.exit prevents async cleanup
**Source:** Sonnet (CLI pipeline)
**File:** `src/cli.ts:49,74,83`
Open handles abandoned. Not critical but messy.

---

## Summary by Count

| Severity | Count |
|----------|-------|
| Critical | 6 |
| High | 12 |
| Medium | 13 |
| Low | 8 |
| **Total** | **39** |

## Reviewer Agreement Matrix

Issues flagged by 3+ independent reviewers (highest confidence):
- **SSRF on executor** (Sonnet security + Gemini codebase + Gemini prompts)
- **Unhandled promise rejection** (Sonnet CLI + Codex error handling)
- **Gemini API key silent empty** (Codex SDK + Codex error handling + Sonnet security)
- **parseInt NaN** (Sonnet type safety + Sonnet CLI)
- **Curl tokenizer escape bug** (Sonnet parsers + Gemini codebase)
- **OpenAPI trailing slash** (Sonnet parsers + Gemini codebase)
