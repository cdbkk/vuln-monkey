import { describe, it, expect } from "vitest";
import { execFileSync } from "node:child_process";

const CWD = "/Users/connor/Dev/vuln-monkey";

describe("CLI smoke tests", () => {
  it("--help outputs expected text", () => {
    const output = execFileSync("npx", ["tsx", "src/cli.ts", "--help"], {
      encoding: "utf-8",
      cwd: CWD,
    });
    expect(output).toContain("AI-powered API security fuzzer");
    expect(output).toContain("--spec");
    expect(output).toContain("--dry-run");
  });

  it("--version outputs version", () => {
    const output = execFileSync("npx", ["tsx", "src/cli.ts", "--version"], {
      encoding: "utf-8",
      cwd: CWD,
    });
    expect(output).toContain("0.1.0");
  });

  it("no args prints error and exits non-zero", () => {
    expect(() => {
      execFileSync("npx", ["tsx", "src/cli.ts"], {
        encoding: "utf-8",
        cwd: CWD,
        stdio: ["pipe", "pipe", "pipe"],
      });
    }).toThrow();

    try {
      execFileSync("npx", ["tsx", "src/cli.ts"], {
        encoding: "utf-8",
        cwd: CWD,
        stdio: ["pipe", "pipe", "pipe"],
      });
    } catch (err: unknown) {
      const e = err as { stderr?: string };
      expect(e.stderr).toContain("Provide a curl command or --spec");
    }
  });
});
