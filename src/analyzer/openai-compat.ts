import type { Endpoint, Vulnerability, AttackPayload, LLMProvider } from "../types.js";
import { buildAnalysisPrompt, buildPayloadPrompt, parseVulnerabilities, parsePayloads } from "./prompts.js";

const DEFAULT_MODEL = "gpt-4o";
const DEFAULT_BASE_URL = "https://api.openai.com/v1";
const TIMEOUT_MS = 120_000;
const MAX_RETRIES = 2;
const RETRY_DELAY_MS = 1000;
const SEND_COMPAT_API_KEY = "OPENAI_COMPAT_SEND_API_KEY";

interface ChatCompletionResponse {
  choices: Array<{
    message: { content: string };
  }>;
}

function isOpenAIHost(baseUrl: string): boolean {
  try {
    return new URL(baseUrl).hostname.toLowerCase() === "api.openai.com";
  } catch {
    return false;
  }
}

function isLocalHost(baseUrl: string): boolean {
  try {
    const host = new URL(baseUrl).hostname.toLowerCase();
    return host === "localhost" || host.endsWith(".localhost") || host.startsWith("127.") || host === "0.0.0.0" || host === "::1" || host === "[::1]";
  } catch {
    return false;
  }
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
    if (!this.apiKey && isOpenAIHost(this.baseUrl)) {
      throw new Error("OPENAI_API_KEY environment variable is required for OpenAI API");
    }
  }

  private shouldSendApiKey(): boolean {
    if (!this.apiKey || isLocalHost(this.baseUrl)) return false;
    return isOpenAIHost(this.baseUrl) || process.env[SEND_COMPAT_API_KEY] === "1";
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
        if (this.shouldSendApiKey()) {
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

        if (!response.ok) {
          const body = await response.text();
          throw new Error(`OpenAI API ${response.status}: ${body.slice(0, 200)}`);
        }

        const data = (await response.json()) as ChatCompletionResponse;
        clearTimeout(timer);
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
