import { describe, it, expect } from "vitest";
import { execFileSync } from "node:child_process";
import { resolve } from "node:path";

const CWD = resolve(import.meta.dirname, "../..");
const EXEC_OPTS = { encoding: "utf-8" as const, cwd: CWD, timeout: 15000 };

describe("CLI smoke tests", () => {
  it("--help outputs expected text", () => {
    const output = execFileSync("npx", ["tsx", "src/cli.ts", "--help"], EXEC_OPTS);
    expect(output).toContain("AI-powered API security fuzzer");
    expect(output).toContain("--spec");
    expect(output).toContain("--dry-run");
  });

  it("--version outputs version", () => {
    const output = execFileSync("npx", ["tsx", "src/cli.ts", "--version"], EXEC_OPTS);
    expect(output).toContain("0.1.0");
  });

  it("no args prints error and exits non-zero", () => {
    try {
      execFileSync("npx", ["tsx", "src/cli.ts"], {
        ...EXEC_OPTS,
        stdio: ["pipe", "pipe", "pipe"],
      });
      throw new Error("Expected CLI to exit non-zero");
    } catch (err: unknown) {
      const e = err as { stderr?: string; message?: string };
      // Verify it actually threw from the CLI, not from our sentinel above
      expect(e.message).not.toBe("Expected CLI to exit non-zero");
      expect(e.stderr).toContain("Provide a curl command or --spec");
    }
  });

  it("--model invalid produces an error containing 'Invalid model'", () => {
    try {
      execFileSync(
        "npx",
        ["tsx", "src/cli.ts", "--model", "invalid", "--spec", "openapi.yaml"],
        { ...EXEC_OPTS, stdio: ["pipe", "pipe", "pipe"] },
      );
      throw new Error("Expected CLI to exit non-zero");
    } catch (err: unknown) {
      const e = err as { stderr?: string; stdout?: string; message?: string };
      expect(e.message).not.toBe("Expected CLI to exit non-zero");
      const output = (e.stderr ?? "") + (e.stdout ?? "");
      expect(output).toContain("Invalid model");
    }
  });

  it("--concurrency foo produces an error containing 'positive integer'", () => {
    try {
      execFileSync(
        "npx",
        ["tsx", "src/cli.ts", "--concurrency", "foo", "--spec", "openapi.yaml"],
        { ...EXEC_OPTS, stdio: ["pipe", "pipe", "pipe"] },
      );
      throw new Error("Expected CLI to exit non-zero");
    } catch (err: unknown) {
      const e = err as { stderr?: string; stdout?: string; message?: string };
      expect(e.message).not.toBe("Expected CLI to exit non-zero");
      const output = (e.stderr ?? "") + (e.stdout ?? "");
      expect(output).toContain("positive integer");
    }
  });
});
