import type { Endpoint, Vulnerability, AttackPayload, LLMProvider } from "../types.js";
import { buildAnalysisPrompt, buildPayloadPrompt, parseVulnerabilities, parsePayloads } from "./prompts.js";

const DEFAULT_MODEL = "gpt-4o";
const DEFAULT_BASE_URL = "https://api.openai.com/v1";
const TIMEOUT_MS = 120_000;
const MAX_RETRIES = 2;
const RETRY_DELAY_MS = 1000;

interface ChatCompletionResponse {
  choices: Array<{
    message: { content: string };
  }>;
}

export class OpenAICompatProvider implements LLMProvider {
  private baseUrl: string;
  private apiKey: string;
  private model: string;

  constructor(modelName?: string) {
    this.baseUrl = (process.env.OPENAI_BASE_URL || process.env.OPENAI_API_BASE || DEFAULT_BASE_URL).replace(/\/$/, "");
    this.apiKey = process.env.OPENAI_API_KEY || "";
    this.model = modelName || process.env.OPENAI_MODEL || DEFAULT_MODEL;

    // Local LLMs often don't need a key, so only require it for openai.com
    if (!this.apiKey && this.baseUrl.includes("api.openai.com")) {
      throw new Error("OPENAI_API_KEY environment variable is required for OpenAI API");
    }
  }

  private async chat(prompt: string): Promise<string> {
    let lastError: unknown;

    for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
      if (attempt > 0) {
        await new Promise((r) => setTimeout(r, RETRY_DELAY_MS));
      }

      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);

      try {
        const headers: Record<string, string> = {
          "Content-Type": "application/json",
        };
        if (this.apiKey) {
          headers["Authorization"] = `Bearer ${this.apiKey}`;
        }

        const response = await fetch(`${this.baseUrl}/chat/completions`, {
          method: "POST",
          headers,
          body: JSON.stringify({
            model: this.model,
            messages: [{ role: "user", content: prompt }],
            temperature: 0.7,
            max_tokens: 8192,
          }),
          signal: controller.signal,
        });

        clearTimeout(timer);

        if (!response.ok) {
          const body = await response.text();
          throw new Error(`OpenAI API ${response.status}: ${body.slice(0, 200)}`);
        }

        const data = (await response.json()) as ChatCompletionResponse;
        return data.choices[0]?.message?.content || "";
      } catch (err) {
        clearTimeout(timer);
        lastError = err;
      }
    }

    throw lastError;
  }

  async analyze(endpoint: Endpoint): Promise<Vulnerability[]> {
    const raw = await this.chat(buildAnalysisPrompt(endpoint));
    return parseVulnerabilities(raw, endpoint.url);
  }

  async generatePayloads(endpoint: Endpoint, vulnerabilities: Vulnerability[]): Promise<AttackPayload[]> {
    const raw = await this.chat(buildPayloadPrompt(endpoint, vulnerabilities));
    return parsePayloads(raw);
  }
}
