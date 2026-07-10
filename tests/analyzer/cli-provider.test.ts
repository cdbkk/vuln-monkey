import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { existsSync, readFileSync, readdirSync } from "node:fs";
import type { Endpoint } from "../../src/types.js";

const { execFileMock, stdinEnd } = vi.hoisted(() => ({
  execFileMock: vi.fn(),
  stdinEnd: vi.fn(),
}));

vi.mock("node:child_process", () => ({ execFile: execFileMock }));

import { CLIProvider } from "../../src/analyzer/cli-provider.js";

const ENDPOINT: Endpoint = {
  method: "GET",
  url: "https://api.example.com/users",
  headers: {},
  auth: { type: "none" },
};

function cliInvocation(command: string) {
  const [actualCommand, rawArgs, options] = execFileMock.mock.calls[0];
  if (process.platform === "win32") {
    expect(actualCommand.toLowerCase()).toBe((process.env.ComSpec ?? "cmd.exe").toLowerCase());
    expect(rawArgs.slice(0, 4)).toEqual(["/d", "/s", "/c", command]);
    return { args: rawArgs.slice(4), options };
  }
  expect(actualCommand).toBe(command);
  return { args: rawArgs, options };
}

describe("CLIProvider", () => {
  beforeEach(() => {
    execFileMock.mockImplementation((command, args, options, callback) => {
      const files = readdirSync(options.cwd);
      expect(files.every((file) => file === "deny-tools.toml")).toBe(true);
      if (command === "gemini") {
        const policyPath = args.at(-1);
        expect(readFileSync(policyPath, "utf-8")).toContain('toolName = "*"');
        expect(readFileSync(policyPath, "utf-8")).toContain('decision = "deny"');
      }
      callback(null, "[]", "");
      return { stdin: { end: stdinEnd } };
    });
  });

  afterEach(() => {
    vi.clearAllMocks();
    delete process.env.VULN_MONKEY_UNRELATED_SECRET;
  });

  it.each([
    ["claude-cli", "claude"],
    ["gemini-cli", "gemini"],
    ["codex-cli", "codex"],
  ])("passes the prompt through stdin for %s", async (backend, command) => {
    await new CLIProvider(backend).analyze(ENDPOINT);

    const { args } = cliInvocation(command);
    expect(args.join(" ")).not.toContain(ENDPOINT.url);
    expect(stdinEnd).toHaveBeenCalledWith(expect.stringContaining(ENDPOINT.url));
  });

  it("keeps full-auto inside an ephemeral read-only Codex run", async () => {
    process.env.VULN_MONKEY_UNRELATED_SECRET = "do-not-inherit";
    await new CLIProvider("codex-cli").analyze(ENDPOINT);

    const { args, options } = cliInvocation("codex");
    expect(args.slice(0, 9)).toEqual([
      "exec", "--full-auto", "--sandbox", "read-only", "--ephemeral",
      "--ignore-user-config", "--ignore-rules", "--skip-git-repo-check", "--disable",
    ]);
    expect(args).toContain("shell_tool");
    expect(args).toContain("unified_exec");
    expect(args.at(-1)).toBe("-");
    expect(options.cwd).toContain("vuln-monkey-");
    expect(existsSync(options.cwd)).toBe(false);
    expect(options.env.VULN_MONKEY_UNRELATED_SECRET).toBeUndefined();
  });

  it("uses ComSpec explicitly for Windows CLI shims", async () => {
    const platform = vi.spyOn(process, "platform", "get").mockReturnValue("win32");
    try {
      await new CLIProvider("codex-cli").analyze(ENDPOINT);

      const [command, args, options] = execFileMock.mock.calls[0];
      expect(command).toBe(process.env.ComSpec ?? "cmd.exe");
      expect(args.slice(0, 4)).toEqual(["/d", "/s", "/c", "codex"]);
      expect(options.shell).toBeUndefined();
      if (process.env.ComSpec) {
        const inherited = Object.entries(options.env)
          .find(([key]) => key.toUpperCase() === "COMSPEC")?.[1];
        expect(inherited).toBe(process.env.ComSpec);
      }
      expect(stdinEnd).toHaveBeenCalled();
    } finally {
      platform.mockRestore();
    }
  });

  it("denies every Gemini tool", async () => {
    await new CLIProvider("gemini-cli").analyze(ENDPOINT);

    const [, args] = execFileMock.mock.calls[0];
    expect(args).toContain("--policy");
    expect(stdinEnd).toHaveBeenCalled();
  });

  it("does not echo untrusted subprocess stderr", async () => {
    execFileMock.mockImplementationOnce((_command, _args, _options, callback) => {
      const error = Object.assign(new Error("unsafe-secret"), { code: 1 });
      callback(error, "", "unsafe-secret");
      return { stdin: { end: stdinEnd } };
    });

    const error = await new CLIProvider("codex-cli").analyze(ENDPOINT)
      .catch((caught: unknown) => caught);
    expect(error).toBeInstanceOf(Error);
    expect((error as Error).message).toBe("codex exited with code 1");
    expect((error as Error).message).not.toContain("unsafe-secret");
  });
});
