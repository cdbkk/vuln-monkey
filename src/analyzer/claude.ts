import Anthropic from "@anthropic-ai/sdk";
import type { Endpoint, Vulnerability, AttackPayload, LLMProvider } from "../types.js";
import { buildAnalysisPrompt, buildPayloadPrompt, parseVulnerabilities, parsePayloads } from "./prompts.js";

const DEFAULT_CLAUDE_MODEL = "claude-sonnet-4-6";

export class ClaudeProvider implements LLMProvider {
  private client: Anthropic;
  private modelName: string;

  constructor(modelName?: string) {
    this.modelName = modelName ?? DEFAULT_CLAUDE_MODEL;
    this.client = new Anthropic({ timeout: 60000 });
  }

  async analyze(endpoint: Endpoint): Promise<Vulnerability[]> {
    const response = await this.client.messages.create({
      model: this.modelName,
      max_tokens: 4096,
      messages: [{ role: "user", content: buildAnalysisPrompt(endpoint) }],
    });
    const text = response.content[0].type === "text" ? response.content[0].text : "";
    return parseVulnerabilities(text, endpoint.url);
  }

  async generatePayloads(endpoint: Endpoint, vulnerabilities: Vulnerability[]): Promise<AttackPayload[]> {
    const response = await this.client.messages.create({
      model: this.modelName,
      max_tokens: 8192,
      messages: [{ role: "user", content: buildPayloadPrompt(endpoint, vulnerabilities) }],
    });
    const text = response.content[0].type === "text" ? response.content[0].text : "";
    return parsePayloads(text);
  }
}
