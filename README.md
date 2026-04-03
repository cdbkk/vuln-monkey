<p align="center">
  <img src=".github/banner.svg" alt="vuln-monkey banner" width="900">
</p>

<p align="center">
  <a href="https://github.com/cdbkk/vuln-monkey/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/cdbkk/vuln-monkey/ci.yml?style=for-the-badge&color=27c93f&label=CI" alt="CI"></a>
  <a href="https://www.npmjs.com/package/vuln-monkey"><img src="https://img.shields.io/npm/v/vuln-monkey?style=for-the-badge&color=e74c3c" alt="npm"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue?style=for-the-badge" alt="License"></a>
  <a href="https://github.com/cdbkk/vuln-monkey/stargazers"><img src="https://img.shields.io/github/stars/cdbkk/vuln-monkey?style=for-the-badge&color=ffbd2e" alt="Stars"></a>
</p>

<p align="center">
  Paste a curl command. Get a vulnerability report.<br/>
  No API keys needed. Works with your existing Claude, Gemini, or Codex subscription.
</p>

<p align="center">
  <a href="#quick-start">Quick Start</a> &nbsp;&bull;&nbsp;
  <a href="#models">Models</a> &nbsp;&bull;&nbsp;
  <a href="#how-it-works">How It Works</a> &nbsp;&bull;&nbsp;
  <a href="#options">Options</a> &nbsp;&bull;&nbsp;
  <a href="#safety">Safety</a>
</p>

---

<br/>

## Quick Start

```bash
npm install -g vuln-monkey
```

```bash
vuln-monkey "curl -X POST https://api.example.com/users \
  -H 'Authorization: Bearer tok123' \
  -d '{\"name\":\"test\"}'"
```

That's it. It uses your Claude Code subscription by default. Zero config.

<br/>

## Demo

```
$ vuln-monkey "curl -X POST https://api.example.com/users -H 'Authorization: Bearer tok' -d '{\"name\":\"test\"}'"

✔ Parsed 1 endpoint(s)
✔ Found 5 potential vulnerabilities
✔ Generated 42 payloads

[1/42]  200  23ms  IDOR - Access user 2's profile
[2/42]  200  31ms  IDOR - Access user 999
[3/42]  500  89ms  Injection - SQL in name field
[4/42]  401  12ms  Auth bypass - No token
[5/42]  200  28ms  Mass assignment - Set role to admin
...

VULN MONKEY REPORT
Target:             https://api.example.com/users
Model:              claude-cli
Endpoints scanned:  1
Payloads fired:     42
Duration:           14.23s
Findings:           8
Risk score: 67/100
Risk rating:        Needs Attention

 CRITICAL  CRASH: Injection - SQL in name field — https://api.example.com/users
 HIGH      ERROR: Type juggling - Integer as name — https://api.example.com/users
 MEDIUM    SUSPICIOUS: IDOR - Access user 2's profile — https://api.example.com/users

Reports written:
  Markdown: ./reports/vuln-monkey-2026-04-03T12-00-00.000Z-a3f2c1.md
  JSON:     ./reports/vuln-monkey-2026-04-03T12-00-00.000Z-a3f2c1.json
```

<br/>

## Models

8 backends. Pick what you have.

<details open>
<summary><b>CLI backends</b> &mdash; use your existing subscriptions, zero config</summary>

<br/>

| Model | What it uses | You need |
|:------|:------------|:---------|
| **`claude-cli`** | Claude Code CLI | `claude` installed |
| **`gemini-cli`** | Gemini CLI | `gemini` installed |
| **`codex-cli`** | Codex CLI | `codex` installed |

```bash
vuln-monkey "curl https://api.example.com/users"                        # claude (default)
vuln-monkey --model gemini-cli "curl https://api.example.com/users"     # gemini
vuln-monkey --model codex-cli "curl https://api.example.com/users"      # codex
```

</details>

<details>
<summary><b>API backends</b> &mdash; for CI, automation, or direct API access</summary>

<br/>

| Model | What it uses | Env var |
|:------|:------------|:--------|
| **`claude`** | Anthropic API | `ANTHROPIC_API_KEY` |
| **`gemini`** | Google Generative AI | `GEMINI_API_KEY` |
| **`openai`** | OpenAI API (GPT-4o, etc.) | `OPENAI_API_KEY` |

```bash
ANTHROPIC_API_KEY=sk-... vuln-monkey --model claude "curl https://api.example.com/users"
OPENAI_API_KEY=sk-... vuln-monkey --model openai "curl https://api.example.com/users"
```

</details>

<details>
<summary><b>Local LLMs</b> &mdash; run entirely on your machine</summary>

<br/>

| Model | What it uses | Config |
|:------|:------------|:-------|
| **`ollama`** | Ollama (localhost:11434) | Just `ollama serve` |
| **`local`** | Any OpenAI-compatible server | `OPENAI_BASE_URL` |

Works with Ollama, LM Studio, vLLM, llama.cpp, text-generation-webui, or anything serving `/v1/chat/completions`.

```bash
# Ollama (auto-connects to localhost:11434)
vuln-monkey --model ollama "curl https://api.example.com/users"

# LM Studio, vLLM, or any OpenAI-compatible server
OPENAI_BASE_URL=http://localhost:1234/v1 vuln-monkey --model local "curl https://api.example.com/users"
```

</details>

<br/>

## How It Works

```
                  ┌──────────────────────┐
                  │  curl / OpenAPI spec  │
                  └──────────┬───────────┘
                             │
                  ┌──────────▼───────────┐
                  │   Parse endpoints    │
                  └──────────┬───────────┘
                             │
                  ┌──────────▼───────────┐
                  │   LLM analysis       │──▶ IDOR, injection, auth bypass, ...
                  └──────────┬───────────┘
                             │
                  ┌──────────▼───────────┐
                  │  Generate payloads   │──▶ 8-10 attack variants per vuln
                  └──────────┬───────────┘
                             │
                  ┌──────────▼───────────┐
                  │   Fire requests      │──▶ Concurrent, with SSRF protection
                  └──────────┬───────────┘
                             │
                  ┌──────────▼───────────┐
                  │  Classify & score    │──▶ pass / suspicious / error / crash
                  └──────────┬───────────┘
                             │
                  ┌──────────▼───────────┐
                  │   Report             │──▶ Terminal + Markdown + JSON
                  └──────────────────────┘
```

<br/>

## Options

| Flag | Description | Default |
|:-----|:-----------|:--------|
| `--spec <url>` | OpenAPI/Swagger spec URL | |
| `--model <name>` | LLM backend (see [Models](#models)) | `claude-cli` |
| `--output <dir>` | Report output directory | `./reports` |
| `--concurrency <n>` | Parallel requests | `5` |
| `--timeout <ms>` | Request timeout in milliseconds | `10000` |
| `--dry-run` | Generate payloads without firing | `false` |

**Input modes:**

```bash
# Curl mode — paste any curl command
vuln-monkey "curl -X POST https://api.example.com/users -d '{\"name\":\"test\"}'"

# OpenAPI mode — point at a spec, fuzz every endpoint
vuln-monkey --spec https://api.example.com/openapi.json

# Dry run — preview the attack plan without sending requests
vuln-monkey --dry-run "curl https://api.example.com/users"
```

<br/>

## Risk Scoring

Each finding gets a severity weight. Summed and capped at 100.

| Severity | Weight | | Score | Rating |
|:---------|:------:|---|:------|:-------|
| Critical | 25 | | > 70 | **Fail** |
| High | 15 | | 40 - 70 | **Needs Attention** |
| Medium | 5 | | < 40 | **Acceptable** |
| Low | 2 | | | |

<br/>

<details>
<summary><b>Vulnerability categories</b></summary>

<br/>

IDOR, BOLA, injection, auth bypass, mass assignment, type juggling, rate limiting bypass, race conditions, overflow, excessive data exposure, CORS misconfiguration, information disclosure.

</details>

<br/>

## Safety

vuln-monkey is a security tool with built-in guardrails:

| Protection | What it does |
|:-----------|:------------|
| **SSRF guard** | Blocks requests to localhost, private IPs, link-local, cloud metadata |
| **Redirect control** | Does not follow HTTP redirects |
| **Response cap** | 1 MB max response body to prevent memory exhaustion |
| **Credential redaction** | Authorization headers masked in Markdown reports |
| **Path validation** | Blocks report writes to sensitive system directories |

> **This tool is for authorized security testing only.** Always get written permission before testing APIs you don't own.

<br/>

## Tech Stack

<p>
  <img src="https://img.shields.io/badge/TypeScript-3178C6?style=for-the-badge&logo=typescript&logoColor=white" alt="TypeScript">
  <img src="https://img.shields.io/badge/Node.js-339933?style=for-the-badge&logo=nodedotjs&logoColor=white" alt="Node.js">
  <img src="https://img.shields.io/badge/Zod-3E67B1?style=for-the-badge&logo=zod&logoColor=white" alt="Zod">
  <img src="https://img.shields.io/badge/Vitest-6E9F18?style=for-the-badge&logo=vitest&logoColor=white" alt="Vitest">
  <img src="https://img.shields.io/badge/Claude-CC785C?style=for-the-badge&logo=anthropic&logoColor=white" alt="Claude">
  <img src="https://img.shields.io/badge/Gemini-4285F4?style=for-the-badge&logo=google&logoColor=white" alt="Gemini">
  <img src="https://img.shields.io/badge/OpenAI-412991?style=for-the-badge&logo=openai&logoColor=white" alt="OpenAI">
  <img src="https://img.shields.io/badge/Ollama-000000?style=for-the-badge&logo=ollama&logoColor=white" alt="Ollama">
</p>

<br/>

## Development

```bash
git clone https://github.com/cdbkk/vuln-monkey.git
cd vuln-monkey
npm install
npm test              # 68 tests
npx tsc --noEmit      # type check
npm run dev -- --help # run locally
```

<br/>

## Requirements

- Node.js 20+
- One of: `claude` CLI, `gemini` CLI, `codex` CLI, an API key, or a local LLM

<br/>

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for setup and guidelines.

<br/>

## License

[MIT](LICENSE)

<br/>

---

<p align="center">
  Built with Claude Code.
</p>
