# Vuln Monkey AI Design

API security fuzzer that uses LLMs to find logic flaws, not just crash endpoints.

## Architecture

```
Input (OpenAPI URL or curl)
  > Parser (normalize to endpoint list)
  > LLM Analysis (identify 5 logic flaws per endpoint)
  > Payload Generator (50 attack payloads per endpoint)
  > Executor (fire at staging URL, collect responses)
  > Reporter (terminal + markdown + JSON)
```

## CLI Interface

```bash
# Curl mode (single endpoint)
npx vuln-monkey "curl -X POST https://staging.api.com/users -H 'Authorization: Bearer xxx' -d '{\"name\":\"test\"}'"

# OpenAPI mode (full spec)
npx vuln-monkey --spec https://staging.api.com/openapi.json

# Options
--model claude|gemini     # LLM backend (default: claude)
--output ./reports        # Report directory
--concurrency 5           # Parallel requests
--timeout 10000           # Request timeout ms
--dry-run                 # Generate payloads but don't fire
```

## Core Modules

### Parser (src/parser/)
Two paths, one output format.
- `curl.ts` parses a curl string into `{ method, url, headers, body }`
- `openapi.ts` fetches and parses OpenAPI 3.x spec into an endpoint list
- Both produce `Endpoint[]` with method, url, headers, body schema, auth info

### Analyzer (src/analyzer/)
Sends each endpoint to the LLM.
- Provider abstraction: `claude.ts` and `gemini.ts` behind a common interface
- Prompt: "Given this endpoint schema, identify 5 potential vulnerabilities from: IDOR, type juggling, mass assignment, rate limiting bypass, auth bypass, injection, overflow, race conditions. For each, explain the attack vector in one sentence."
- Output: `Vulnerability[]` with type, description, severity estimate

### Generator (src/generator/)
Turns vulnerabilities into payloads.
- LLM generates 8 to 10 attack payloads per vulnerability
- Each payload is a complete request: method, url (with path manipulation), headers, body
- Categories: boundary values, type confusion, injection strings, auth manipulation, oversized inputs

### Executor (src/executor/)
Fires payloads with controlled concurrency.
- Uses undici or fetch for HTTP
- Captures: status code, response time, response body (truncated), headers
- Classifies results: pass (2xx expected), suspicious (unexpected 2xx on attack), error (4xx/5xx with stack trace leak), crash (5xx/timeout)

### Reporter (src/reporter/)
Three outputs.
- Terminal: Rich live output via chalk + ora. Progress bar, color coded hits as they happen.
- Markdown: Full audit report. Executive summary, risk score, findings table, raw payload/response pairs.
- JSON: Machine readable, same data structure, for CI/CD integration.

## Risk Score (0 to 100)

Weighted formula:
- Critical findings (stack trace leak, auth bypass, IDOR confirmed): 25 points each
- High (unexpected 2xx on destructive payload): 15 points each
- Medium (verbose error messages, timing anomalies): 5 points each
- Low (missing headers, rate limit absent): 2 points each
- Capped at 100. Above 70 = Fail, 40 to 70 = Needs attention, below 40 = Acceptable

## Tech Stack

- Runtime: Node.js / Bun, TypeScript
- HTTP: undici
- CLI: commander
- Terminal UI: chalk + ora
- Schema parsing: openapi-types, zod for internal types
- LLM: @anthropic-ai/sdk for Claude, @google/generative-ai for Gemini
- Package: Published to npm as vuln-monkey

## File Structure

```
vuln-monkey/
  src/
    cli.ts
    types.ts
    parser/
      curl.ts
      openapi.ts
    analyzer/
      provider.ts
      claude.ts
      gemini.ts
      prompts.ts
    generator/
      payloads.ts
    executor/
      runner.ts
    reporter/
      terminal.ts
      markdown.ts
      json.ts
      score.ts
  tests/
  package.json
  tsconfig.json
  README.md
```
