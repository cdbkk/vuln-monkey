import { GoogleGenerativeAI } from "@google/generative-ai";
import type { Endpoint, Vulnerability, AttackPayload, LLMProvider } from "../types.js";
import { buildAnalysisPrompt, buildPayloadPrompt, parseVulnerabilities, parsePayloads } from "./prompts.js";

export class GeminiProvider implements LLMProvider {
  private model;

  constructor() {
    const apiKey = process.env.GEMINI_API_KEY;
    if (!apiKey) {
      throw new Error("GEMINI_API_KEY environment variable is required");
    }
    const genAI = new GoogleGenerativeAI(apiKey);
    this.model = genAI.getGenerativeModel({ model: "gemini-2.5-flash" });
  }

  async analyze(endpoint: Endpoint): Promise<Vulnerability[]> {
    const result = await this.model.generateContent(buildAnalysisPrompt(endpoint));
    const text = result.response.text();
    return parseVulnerabilities(text, endpoint.url);
  }

  async generatePayloads(endpoint: Endpoint, vulnerabilities: Vulnerability[]): Promise<AttackPayload[]> {
    const result = await this.model.generateContent(buildPayloadPrompt(endpoint, vulnerabilities));
    const text = result.response.text();
    return parsePayloads(text);
  }
}
