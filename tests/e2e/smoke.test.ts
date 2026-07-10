import { describe, it, expect } from "vitest";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const CWD = resolve(import.meta.dirname, "../..");
const EXEC_OPTS = { encoding: "utf-8" as const, cwd: CWD, timeout: 15000 };
const PKG_VERSION = JSON.parse(readFileSync(resolve(CWD, "package.json"), "utf-8")).version;
const CLI_ARGS = [resolve(CWD, "node_modules/tsx/dist/cli.mjs"), "src/cli.ts"];

describe("CLI smoke tests", () => {
  it("--help outputs expected text", () => {
    const output = execFileSync(process.execPath, [...CLI_ARGS, "--help"], EXEC_OPTS);
    expect(output).toContain("AI-powered API security fuzzer");
    expect(output).toContain("--spec");
    expect(output).toContain("--header");
    expect(output).toContain("--credential-origin");
    expect(output).toContain("--fail-on");
    expect(output).toContain("--allow-private");
    expect(output).toContain("--dry-run");
  });

  it("--version outputs version", () => {
    const output = execFileSync(process.execPath, [...CLI_ARGS, "--version"], EXEC_OPTS);
    expect(output).toContain(PKG_VERSION);
  });

  it("no args prints error and exits non-zero", () => {
    try {
      execFileSync(process.execPath, CLI_ARGS, {
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
        process.execPath,
        [...CLI_ARGS, "--model", "invalid", "--spec", "openapi.yaml"],
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
        process.execPath,
        [...CLI_ARGS, "--concurrency", "foo", "--spec", "openapi.yaml"],
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

  it("rejects curl and --spec together", () => {
    try {
      execFileSync(
        process.execPath,
        [...CLI_ARGS, "curl https://example.com", "--spec", "https://example.com/openapi.json"],
        { ...EXEC_OPTS, stdio: ["pipe", "pipe", "pipe"] },
      );
      throw new Error("Expected CLI to exit non-zero");
    } catch (err: unknown) {
      const e = err as { stderr?: string; stdout?: string; message?: string };
      expect(e.message).not.toBe("Expected CLI to exit non-zero");
      expect((e.stderr ?? "") + (e.stdout ?? "")).toContain("not both");
    }
  });

  it("requires an explicit credential origin for OpenAPI headers", () => {
    try {
      execFileSync(
        process.execPath,
        [...CLI_ARGS, "--spec", "https://example.com/openapi.json", "-H", "Authorization: Bearer test"],
        { ...EXEC_OPTS, stdio: ["pipe", "pipe", "pipe"] },
      );
      throw new Error("Expected CLI to exit non-zero");
    } catch (err: unknown) {
      const e = err as { stderr?: string; stdout?: string; message?: string };
      expect(e.message).not.toBe("Expected CLI to exit non-zero");
      expect((e.stderr ?? "") + (e.stdout ?? "")).toContain("--credential-origin");
    }
  });

  it("rejects concurrency above the executor cap", () => {
    try {
      execFileSync(
        process.execPath,
        [...CLI_ARGS, "--concurrency", "101", "--spec", "https://example.com/openapi.json"],
        { ...EXEC_OPTS, stdio: ["pipe", "pipe", "pipe"] },
      );
      throw new Error("Expected CLI to exit non-zero");
    } catch (err: unknown) {
      const e = err as { stderr?: string; stdout?: string; message?: string };
      expect(e.message).not.toBe("Expected CLI to exit non-zero");
      expect((e.stderr ?? "") + (e.stdout ?? "")).toContain("at most 100");
    }
  });

  it("rejects timeouts that Node would clamp", () => {
    try {
      execFileSync(
        process.execPath,
        [...CLI_ARGS, "--timeout", "2147483648", "--spec", "https://example.com/openapi.json"],
        { ...EXEC_OPTS, stdio: ["pipe", "pipe", "pipe"] },
      );
      throw new Error("Expected CLI to exit non-zero");
    } catch (err: unknown) {
      const e = err as { stderr?: string; stdout?: string; message?: string };
      expect(e.message).not.toBe("Expected CLI to exit non-zero");
      expect((e.stderr ?? "") + (e.stdout ?? "")).toContain("at most 2147483647");
    }
  });

  it("rejects output symlinks into sensitive directories", () => {
    const tempDir = mkdtempSync(join(tmpdir(), "vuln-monkey-output-"));
    const outputDir = join(tempDir, "reports");
    symlinkSync("/etc", outputDir);
    try {
      execFileSync(
        process.execPath,
        [...CLI_ARGS, "--output", outputDir, "--spec", "https://example.com/openapi.json"],
        { ...EXEC_OPTS, stdio: ["pipe", "pipe", "pipe"] },
      );
      throw new Error("Expected CLI to exit non-zero");
    } catch (err: unknown) {
      const e = err as { stderr?: string; stdout?: string; message?: string };
      expect(e.message).not.toBe("Expected CLI to exit non-zero");
      expect((e.stderr ?? "") + (e.stdout ?? "")).toContain("sensitive system directory");
    } finally {
      rmSync(tempDir, { recursive: true, force: true });
    }
  });
});
