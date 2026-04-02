import Anthropic from "@anthropic-ai/sdk";
import type { Endpoint, Vulnerability, AttackPayload, LLMProvider } from "../types.js";
import { buildAnalysisPrompt, buildPayloadPrompt, parseVulnerabilities, parsePayloads } from "./prompts.js";

export class ClaudeProvider implements LLMProvider {
  private client: Anthropic;

  constructor() {
    this.client = new Anthropic();
  }

  async analyze(endpoint: Endpoint): Promise<Vulnerability[]> {
    const response = await this.client.messages.create({
      model: "claude-sonnet-4-6",
      max_tokens: 4096,
      messages: [{ role: "user", content: buildAnalysisPrompt(endpoint) }],
    });
    const text = response.content[0].type === "text" ? response.content[0].text : "";
    return parseVulnerabilities(text, endpoint.url);
  }

  async generatePayloads(endpoint: Endpoint, vulnerabilities: Vulnerability[]): Promise<AttackPayload[]> {
    const response = await this.client.messages.create({
      model: "claude-sonnet-4-6",
      max_tokens: 8192,
      messages: [{ role: "user", content: buildPayloadPrompt(endpoint, vulnerabilities) }],
    });
    const text = response.content[0].type === "text" ? response.content[0].text : "";
    return parsePayloads(text);
  }
}
