import { execFile } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Endpoint, Vulnerability, AttackPayload, LLMProvider } from "../types.js";
import { buildAnalysisPrompt, buildPayloadPrompt, parseVulnerabilities, parsePayloads } from "./prompts.js";

interface CLIConfig {
  command: string;
  args: string[];
  envPrefixes: string[];
  timeout: number;
}

const COMMON_ENV = new Set([
  "PATH", "HOME", "USERPROFILE", "TMPDIR", "TEMP", "TMP",
  "SYSTEMROOT", "COMSPEC", "PATHEXT",
  "LANG", "LC_ALL", "XDG_CONFIG_HOME", "XDG_CACHE_HOME",
  "SSL_CERT_FILE", "SSL_CERT_DIR", "NODE_EXTRA_CA_CERTS",
  "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
]);
const DENY_ALL_GEMINI_TOOLS = `[[rule]]
toolName = "*"
decision = "deny"
priority = 999

[[rule]]
toolName = "*"
mcpName = "*"
decision = "deny"
priority = 999
`;
const CODEX_DISABLED_FEATURES = [
  "shell_tool",
  "unified_exec",
  "code_mode_host",
  "shell_snapshot",
  "apps",
  "browser_use",
  "browser_use_external",
  "computer_use",
  "multi_agent",
  "hooks",
  "plugins",
];

const CLI_CONFIGS: Record<string, CLIConfig> = {
  "claude-cli": {
    command: "claude",
    args: [
      "-p", "--output-format", "text", "--no-session-persistence",
      "--safe-mode", "--permission-mode", "plan", "--tools", "",
    ],
    envPrefixes: ["ANTHROPIC_", "CLAUDE_CODE_", "AWS_", "GOOGLE_", "AZURE_"],
    timeout: 120_000,
  },
  "gemini-cli": {
    command: "gemini",
    args: ["-p", "", "--approval-mode", "plan", "--output-format", "text"],
    envPrefixes: ["GEMINI_", "GOOGLE_"],
    timeout: 120_000,
  },
  "codex-cli": {
    command: "codex",
    args: [
      "exec", "--full-auto", "--sandbox", "read-only", "--ephemeral",
      "--ignore-user-config", "--ignore-rules", "--skip-git-repo-check",
      ...CODEX_DISABLED_FEATURES.flatMap((feature) => ["--disable", feature]),
      "-",
    ],
    envPrefixes: ["OPENAI_", "CODEX_HOME"],
    timeout: 180_000,
  },
};

function childEnvironment(config: CLIConfig): NodeJS.ProcessEnv {
  return Object.fromEntries(
    Object.entries(process.env).filter(([key]) => {
      const upper = key.toUpperCase();
      return COMMON_ENV.has(upper) || config.envPrefixes.some((prefix) => upper.startsWith(prefix));
    })
  );
}

async function runCLI(config: CLIConfig, prompt: string): Promise<string> {
  const cwd = await mkdtemp(join(tmpdir(), "vuln-monkey-"));
  try {
    const args = [...config.args];
    if (config.command === "gemini") {
      const policyPath = join(cwd, "deny-tools.toml");
      await writeFile(policyPath, DENY_ALL_GEMINI_TOOLS, { mode: 0o600 });
      args.push("--policy", policyPath);
    }
    const command = process.platform === "win32"
      ? process.env.ComSpec ?? "cmd.exe"
      : config.command;
    const commandArgs = process.platform === "win32"
      ? ["/d", "/s", "/c", config.command, ...args]
      : args;
    return await new Promise((resolve, reject) => {
      const proc = execFile(
        command,
        commandArgs,
        {
          cwd,
          env: childEnvironment(config),
          timeout: config.timeout,
          maxBuffer: 10 * 1024 * 1024,
        },
        (error, stdout) => {
          if (error) {
            const reason = error.killed
              ? "timed out"
              : error.code === "ENOENT"
                ? "is not installed or not on PATH"
                : typeof error.code === "number"
                  ? `exited with code ${error.code}`
                  : "failed";
            reject(new Error(`${config.command} ${reason}`));
            return;
          }
          resolve(stdout);
        }
      );
      proc.stdin?.end(prompt);
    });
  } finally {
    await rm(cwd, { recursive: true, force: true });
  }
}

export class CLIProvider implements LLMProvider {
  private config: CLIConfig;
  private label: string;

  constructor(backend: string) {
    const config = CLI_CONFIGS[backend];
    if (!config) {
      throw new Error(`Unknown CLI backend: ${backend}. Available: ${Object.keys(CLI_CONFIGS).join(", ")}`);
    }
    this.config = config;
    this.label = backend;
  }

  async analyze(endpoint: Endpoint): Promise<Vulnerability[]> {
    const prompt = buildAnalysisPrompt(endpoint);
    const raw = await runCLI(this.config, prompt);
    return parseVulnerabilities(raw, endpoint.url);
  }

  async generatePayloads(endpoint: Endpoint, vulnerabilities: Vulnerability[]): Promise<AttackPayload[]> {
    const prompt = buildPayloadPrompt(endpoint, vulnerabilities);
    const raw = await runCLI(this.config, prompt);
    return parsePayloads(raw);
  }
}
