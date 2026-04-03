import { execFile } from "node:child_process";
import type { Endpoint, Vulnerability, AttackPayload, LLMProvider } from "../types.js";
import { buildAnalysisPrompt, buildPayloadPrompt, parseVulnerabilities, parsePayloads } from "./prompts.js";

interface CLIConfig {
  command: string;
  args: (prompt: string) => string[];
  timeout: number;
}

const CLI_CONFIGS: Record<string, CLIConfig> = {
  "claude-cli": {
    command: "claude",
    args: (prompt) => ["-p", "--", prompt, "--output-format", "text"],
    timeout: 120_000,
  },
  "gemini-cli": {
    command: "gemini",
    args: (prompt) => ["-p", "--", prompt],
    timeout: 120_000,
  },
  "codex-cli": {
    command: "codex",
    args: (prompt) => ["exec", "--", prompt, "--full-auto"],
    timeout: 180_000,
  },
};

function runCLI(config: CLIConfig, prompt: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const proc = execFile(
      config.command,
      config.args(prompt),
      { timeout: config.timeout, maxBuffer: 10 * 1024 * 1024 },
      (error, stdout, stderr) => {
        if (error) {
          reject(new Error(`${config.command} failed: ${error.message}${stderr ? `\n${stderr}` : ""}`));
          return;
        }
        resolve(stdout);
      }
    );
    proc.stdin?.end();
  });
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
