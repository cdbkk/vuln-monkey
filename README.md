<div align="center">

<pre>
            __                            __
 _   ___  _/ /___       ____ ___  ____  / /_____ __  __
| | / / / / / __ \____ / __ `__ \/ __ \/ //_/ _ \/ / / /
| |/ / /_/ / / / /____/ / / / / / /_/ / ,< /  __/ /_/ /
|___/\__,_/_/ /_/    /_/ /_/ /_/\____/_/|_|\___/\__, /
                                                /____/
</pre>

**AI-powered API security fuzzer.**
Paste a curl command. Get a vulnerability report.

[![CI](https://github.com/cdbkk/vuln-monkey/actions/workflows/ci.yml/badge.svg)](https://github.com/cdbkk/vuln-monkey/actions/workflows/ci.yml)
[![npm version](https://img.shields.io/npm/v/vuln-monkey.svg)](https://www.npmjs.com/package/vuln-monkey)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

</div>

---

vuln-monkey takes a curl command or OpenAPI spec, sends it to an LLM for vulnerability analysis, generates attack payloads, fires them with controlled concurrency, classifies the responses, and outputs a risk scored report. Terminal, Markdown, and JSON.

Five LLM backends. Two use API keys. Three use your existing CLI subscriptions with zero config.

## Quick start

```bash
npm install -g vuln-monkey
```

```bash
# Fuzz a single endpoint
vuln-monkey "curl -X POST https://api.example.com/users \
  -H 'Authorization: Bearer tok123' \
  -d '{\"name\":\"test\"}'"

# Fuzz an entire API from its OpenAPI spec
vuln-monkey --spec https://api.example.com/openapi.json

# Preview attack payloads without firing them
vuln-monkey --dry-run "curl https://api.example.com/users"
```

## How it works

```
curl / OpenAPI spec
       |
       v
  Parse endpoints
       |
       v
  LLM analysis -----> Identify vulnerabilities (IDOR, injection, auth bypass, ...)
       |
       v
  Generate payloads -> 8-10 attack variants per vulnerability
       |
       v
  Fire requests -----> Controlled concurrency, timeouts, SSRF protection
       |
       v
  Classify responses -> pass / suspicious / error / crash
       |
       v
  Score & report -----> 0-100 risk score, terminal + markdown + JSON output
```

## Models

**CLI backends** (use your existing subscriptions, zero config):

| Model | What it uses |
|-------|-------------|
| `claude-cli` | Your Claude Code subscription |
| `gemini-cli` | Your Gemini CLI subscription |
| `codex-cli` | Your Codex/OpenAI subscription |

**API backends** (use API keys, good for CI/automation):

| Model | What it uses | Env var |
|-------|-------------|---------|
| `claude` | Anthropic API | `ANTHROPIC_API_KEY` |
| `gemini` | Google Generative AI API | `GEMINI_API_KEY` |
| `openai` | OpenAI API (GPT-4o, etc.) | `OPENAI_API_KEY` |
| `ollama` | Ollama local models (localhost:11434) | None |
| `local` | Any OpenAI-compatible server (LM Studio, vLLM, llama.cpp) | `OPENAI_BASE_URL` |

Default is `claude-cli`. No API key needed if you already have Claude Code installed.

```bash
# Use your Claude subscription (default, no config)
vuln-monkey "curl https://api.example.com/users"

# Use Gemini CLI
vuln-monkey --model gemini-cli "curl https://api.example.com/users"

# Use Codex CLI
vuln-monkey --model codex-cli "curl https://api.example.com/users"

# Use OpenAI API directly
OPENAI_API_KEY=sk-... vuln-monkey --model openai "curl https://api.example.com/users"

# Use a local Ollama model
vuln-monkey --model ollama "curl https://api.example.com/users"

# Use any OpenAI-compatible server (LM Studio, vLLM, etc.)
OPENAI_BASE_URL=http://localhost:1234/v1 vuln-monkey --model local "curl https://api.example.com/users"
```

## Options

| Flag | Description | Default |
|------|-------------|---------|
| `--spec <url>` | OpenAPI/Swagger spec URL | |
| `--model <name>` | LLM backend (see above) | `claude-cli` |
| `--output <dir>` | Report output directory | `./reports` |
| `--concurrency <n>` | Parallel requests | `5` |
| `--timeout <ms>` | Request timeout in milliseconds | `10000` |
| `--dry-run` | Generate payloads without firing | `false` |

## Risk scoring

Each finding gets a severity. Severities are weighted and summed, capped at 100.

| Severity | Weight |
|----------|--------|
| Critical | 25 |
| High | 15 |
| Medium | 5 |
| Low | 2 |

| Score | Rating |
|-------|--------|
| > 70 | **Fail** |
| 40 - 70 | **Needs Attention** |
| < 40 | **Acceptable** |

## Vulnerability categories

IDOR, BOLA, injection, auth bypass, mass assignment, type juggling, rate limiting bypass, race conditions, overflow, excessive data exposure, CORS misconfiguration, information disclosure.

## Safety

vuln-monkey includes built-in protections:

- **SSRF guard** blocks requests to localhost, private IPs, link-local, and cloud metadata endpoints
- **Redirect control** does not follow HTTP redirects (prevents redirect-based SSRF)
- **Response size cap** at 1 MB to prevent memory exhaustion
- **Credential redaction** in Markdown reports (Authorization headers masked)
- **Output path validation** blocks writes to sensitive system directories

This tool is for **authorized security testing only**. Always get written permission before testing APIs you don't own.

## Requirements

- Node.js 20+
- One of: `claude` CLI, `gemini` CLI, `codex` CLI, an API key, or a local LLM (Ollama, LM Studio, etc.)

## Development

```bash
git clone https://github.com/cdbkk/vuln-monkey.git
cd vuln-monkey
npm install
npm test              # 68 tests
npx tsc --noEmit      # type check
npm run dev -- --help # run locally
```

## License

[MIT](LICENSE)
