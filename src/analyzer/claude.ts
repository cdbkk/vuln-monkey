import Anthropic from "@anthropic-ai/sdk";
import type { Endpoint, Vulnerability, AttackPayload, LLMProvider } from "../types.js";
import { buildAnalysisPrompt, buildPayloadPrompt, parseVulnerabilities, parsePayloads } from "./prompts.js";

const DEFAULT_CLAUDE_MODEL = "claude-sonnet-4-6";
const CLAUDE_TIMEOUT_MS = 60_000;
const ANALYSIS_MAX_TOKENS = 4096;
const PAYLOAD_MAX_TOKENS = 8192;

export class ClaudeProvider implements LLMProvider {
  private client: Anthropic;
  private modelName: string;

  constructor(modelName?: string) {
    this.modelName = modelName ?? DEFAULT_CLAUDE_MODEL;
    this.client = new Anthropic({ timeout: CLAUDE_TIMEOUT_MS });
  }

  async analyze(endpoint: Endpoint): Promise<Vulnerability[]> {
    const response = await this.client.messages.create({
      model: this.modelName,
      max_tokens: ANALYSIS_MAX_TOKENS,
      messages: [{ role: "user", content: buildAnalysisPrompt(endpoint) }],
    });
    const text = response.content[0].type === "text" ? response.content[0].text : "";
    return parseVulnerabilities(text, endpoint.url);
  }

  async generatePayloads(endpoint: Endpoint, vulnerabilities: Vulnerability[]): Promise<AttackPayload[]> {
    const response = await this.client.messages.create({
      model: this.modelName,
      max_tokens: PAYLOAD_MAX_TOKENS,
      messages: [{ role: "user", content: buildPayloadPrompt(endpoint, vulnerabilities) }],
    });
    const text = response.content[0].type === "text" ? response.content[0].text : "";
    return parsePayloads(text);
  }
}
