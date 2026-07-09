<p align="center">
  <img src="https://cdn.jsdelivr.net/gh/cdbkk/vuln-monkey@main/assets/banner.svg" alt="vuln-monkey — AI-powered API security fuzzer" width="100%">
</p>

<p align="center">
  <a href="https://www.npmjs.com/package/vuln-monkey"><img src="https://img.shields.io/npm/v/vuln-monkey?color=2ea043&label=npm" alt="npm"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue" alt="license"></a>
  <img src="https://img.shields.io/badge/node-%E2%89%A520-brightgreen" alt="node >=20">
  <img src="https://img.shields.io/badge/security-hardened-56d364" alt="security hardened">
</p>

<p align="center">
  <img src="https://cdn.jsdelivr.net/gh/cdbkk/vuln-monkey@main/assets/demo.svg" alt="vuln-monkey terminal demo" width="760">
</p>

vuln-monkey uses an LLM to analyze API endpoints, generate attack payloads, fire them, and classify the responses. It writes a terminal summary plus Markdown and JSON reports. **v0.2.0** hardens security and correctness around that pipeline.

## Quickstart

```bash
# one-shot
npx vuln-monkey "curl -X POST https://api.example.com/users -H 'Authorization: Bearer tok_xxx' -d '{\"name\":\"test\"}'"

# or install globally
npm install -g vuln-monkey
vuln-monkey "curl -X GET https://api.example.com/users/42 -H 'Authorization: Bearer tok_xxx'"
```

Default model is `claude-cli` (your local Claude Code CLI). Reports land in `./reports/`.

OpenAPI instead of curl:

```bash
vuln-monkey --spec https://api.example.com/openapi.json --model openai --concurrency 10
```

## Providers

Select a backend with `--model` (default: `claude-cli`).

### CLI backends (no API key in-process)

| Model | Requires |
|:------|:---------|
| `claude-cli` *(default)* | `claude` CLI on `PATH` |
| `gemini-cli` | `gemini` CLI on `PATH` |
| `codex-cli` | `codex` CLI on `PATH` |

```bash
vuln-monkey --model gemini-cli "curl https://api.example.com/users"
vuln-monkey --model codex-cli "curl https://api.example.com/users"
```

### API backends

| Model | Provider | Env |
|:------|:---------|:----|
| `claude` | Anthropic | `ANTHROPIC_API_KEY` |
| `gemini` | Google Generative AI | `GEMINI_API_KEY` |
| `openai` | OpenAI-compatible HTTP API | `OPENAI_API_KEY` (optional `OPENAI_BASE_URL` / `OPENAI_API_BASE`) |

```bash
ANTHROPIC_API_KEY=sk-... vuln-monkey --model claude "curl https://api.example.com/users"
OPENAI_API_KEY=sk-... vuln-monkey --model openai "curl https://api.example.com/users"
GEMINI_API_KEY=... vuln-monkey --model gemini "curl https://api.example.com/users"
```

### Local / self-hosted

| Model | Default base URL | Notes |
|:------|:-----------------|:------|
| `ollama` | `http://localhost:11434/v1` | Default model name `llama3.1` |
| `local` | `http://localhost:1234/v1` | LM Studio, vLLM, llama.cpp server, etc. |

Both use the OpenAI-compatible client. If `OPENAI_BASE_URL` or `OPENAI_API_BASE` points at a **local** host (`localhost`, `127.*`, `::1`, …), that URL is used instead of the default.

```bash
vuln-monkey --model ollama "curl https://api.example.com/users"
OPENAI_BASE_URL=http://localhost:1234/v1 vuln-monkey --model local "curl https://api.example.com/users"
```

Valid `--model` values: `claude-cli`, `gemini-cli`, `codex-cli`, `claude`, `gemini`, `openai`, `ollama`, `local`.

## Inputs

**Curl command** (positional argument) — parsed into method, URL, headers, body, and auth:

```bash
vuln-monkey "curl -X POST https://api.example.com/login -d '{\"user\":\"a\",\"password\":\"b\"}'"
```

**OpenAPI / Swagger** — fetch a remote spec and fuzz every extracted endpoint:

```bash
vuln-monkey --spec https://api.example.com/openapi.json
```

You must pass a curl string **or** `--spec <url>`.

### CLI options

| Option | Description | Default |
|:-------|:------------|:--------|
| `[curl]` | Curl command to fuzz | — |
| `--spec <url>` | OpenAPI/Swagger spec URL | — |
| `--model <name>` | LLM backend (see above) | `claude-cli` |
| `--output <dir>` | Report output directory | `./reports` |
| `--concurrency <n>` | Parallel request workers | `5` |
| `--timeout <ms>` | Per-request timeout | `10000` |
| `--dry-run` | Generate payloads only; do not send requests | off |

```bash
vuln-monkey --dry-run "curl https://api.example.com/users"
vuln-monkey --model ollama --timeout 20000 --output ./out "curl -X POST https://api.example.com/login -d '{}'"
```

## How it works

1. **Parse** — curl or OpenAPI → endpoint list (method, URL, headers, body, auth).
2. **Analyze** — LLM suggests potential vulnerability types for each endpoint.
3. **Generate payloads** — LLM builds attack requests; if generation fails or returns nothing, a built-in fallback synthesizes common probes (e.g. auth-bypass / mass-assignment style variants).
4. **Execute** — payloads are fired with configurable concurrency and timeout (`--dry-run` stops before this step).
5. **Report** — non-pass results become findings, scored into a risk score / rating, then written out.

### Output

- **Terminal** — live per-payload lines and a summary (target, model, endpoints scanned, payloads fired, findings, risk score/rating, duration).
- **Markdown** — `./reports/…​.md` (or `--output`).
- **JSON** — `./reports/…​.json` for CI / automation.

Risk rating is one of `Fail`, `Needs Attention`, or `Acceptable` (score 0–100).

## Security & safety

This is a **security testing tool**. Only run it against systems you are authorized to test.

v0.2.0 focuses on hardening, not new attack surface:

- **SSRF protections** with DNS pinning on outbound request targets
- **Secret redaction** in generated reports
- **Response-size limits** so large bodies cannot blow up the process
- **LLM-output validation** so malformed model responses do not drive arbitrary execution paths

Also: report paths that resolve into sensitive system directories (`/etc`, `/proc`, …) are rejected; terminal output is sanitized for control characters.

## Limitations

- Results are **LLM-driven** — suggestions and payloads vary by model and can miss issues or invent noise.
- You need a working **CLI backend, API key, or local OpenAI-compatible server**.
- Classifications and findings need **human triage** before you treat them as confirmed vulns.
- Fallback payloads are generic; they are a safety net, not a full replacement for good model output.

## Requirements

- Node.js **≥ 20**
- One of: Claude / Gemini / Codex CLI, or an API key for Claude / Gemini / OpenAI-compatible, or a local model server (Ollama, LM Studio, …)

## Contributing

Issues and PRs welcome at [github.com/cdbkk/vuln-monkey](https://github.com/cdbkk/vuln-monkey).

```bash
git clone https://github.com/cdbkk/vuln-monkey.git
cd vuln-monkey && npm install
npm test
npm run dev -- --help
```

## License

[MIT](LICENSE)