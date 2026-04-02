# vuln-monkey

AI-powered API security fuzzer that uses LLMs to discover logic flaws in your endpoints.

## Install

```
npm install -g vuln-monkey
```

## Usage

**Curl mode** — paste any curl command and vuln-monkey generates and fires attack variants:

```
vuln-monkey "curl -X POST https://api.example.com/users -H 'Authorization: Bearer tok' -d '{\"name\":\"test\"}'"
```

**OpenAPI mode** — point at a spec and it fuzzes every endpoint automatically:

```
vuln-monkey --spec https://api.example.com/openapi.json
```

**Dry run** — preview the generated attack plan without sending any requests:

```
vuln-monkey --dry-run "curl https://api.example.com/users"
```

## Options

| Flag | Description | Default |
|------|-------------|---------|
| `--spec` | OpenAPI/Swagger spec URL or file path | |
| `--model` | LLM backend to use (`claude` or `gemini`) | `claude` |
| `--output` | Write results to a JSON file at this path | |
| `--concurrency` | Number of parallel requests | `5` |
| `--timeout` | Request timeout in milliseconds | `10000` |
| `--dry-run` | Print attack plan without sending requests | `false` |

## Risk Scoring

Each finding is assigned a severity and weighted score:

| Severity | Weight |
|----------|--------|
| Critical | 25 |
| High | 15 |
| Medium | 5 |
| Low | 2 |

The total risk score is the sum of all finding weights, capped at 100.

| Score | Rating |
|-------|--------|
| > 70 | Fail |
| 40 to 70 | Needs Attention |
| < 40 | Acceptable |

## License

MIT
