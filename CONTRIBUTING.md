# Contributing to vuln-monkey

Thanks for your interest in contributing.

## Getting started

```bash
git clone https://github.com/cdbkk/vuln-monkey.git
cd vuln-monkey
npm install
npm test
```

## Development

```bash
npm run dev -- --help          # Run CLI in dev mode
npm test                        # Run tests
npm run test:watch              # Watch mode
npx tsc --noEmit                # Type check
```

## Pull requests

1. Fork the repo and create a branch from `main`.
2. Add tests for any new functionality.
3. Make sure `npx tsc --noEmit` and `npm test` both pass.
4. Open a PR with a clear description of what changed and why.

## Reporting bugs

Open an issue with reproduction steps, expected behavior, and your environment details.

## Code style

Follow the existing patterns. TypeScript strict mode. No `any` at public boundaries. Tests for all new modules.
