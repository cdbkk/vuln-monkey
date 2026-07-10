import type { Endpoint, Vulnerability, AttackPayload, LLMProvider } from "../types.js";
import { buildAnalysisPrompt, buildPayloadPrompt, parseVulnerabilities, parsePayloads } from "./prompts.js";

const DEFAULT_MODEL = "gpt-4o";
const DEFAULT_BASE_URL = "https://api.openai.com/v1";
const TIMEOUT_MS = 120_000;
const MAX_RETRIES = 2;
const RETRY_DELAY_MS = 1000;
const MAX_RETRY_DELAY_MS = 10_000;
const MAX_RESPONSE_BYTES = 1024 * 1024;

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

function isTransientStatus(status: number): boolean {
  return status === 408 || status === 425 || status === 429 || status === 500 || status === 502 || status === 503 || status === 504;
}

function retryDelay(response: Response): number {
  const value = response.headers.get("retry-after");
  if (!value) return RETRY_DELAY_MS;

  const seconds = Number(value);
  const delay = Number.isFinite(seconds) ? seconds * 1000 : Date.parse(value) - Date.now();
  return Number.isFinite(delay) ? Math.min(MAX_RETRY_DELAY_MS, Math.max(0, delay)) : RETRY_DELAY_MS;
}

async function readLimitedBody(response: Response): Promise<string> {
  const declaredSize = Number(response.headers.get("content-length"));
  if (Number.isFinite(declaredSize) && declaredSize > MAX_RESPONSE_BYTES) {
    await response.body?.cancel();
    throw new Error(`OpenAI API response exceeds ${MAX_RESPONSE_BYTES} bytes`);
  }

  if (!response.body) return "";
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  const chunks: string[] = [];
  let size = 0;

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > MAX_RESPONSE_BYTES) {
      await reader.cancel();
      throw new Error(`OpenAI API response exceeds ${MAX_RESPONSE_BYTES} bytes`);
    }
    chunks.push(decoder.decode(value, { stream: true }));
  }

  chunks.push(decoder.decode());
  return chunks.join("");
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

  private async chat(prompt: string): Promise<string> {
    let lastError: unknown;
    let delay = RETRY_DELAY_MS;

    for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
      if (attempt > 0) {
        await new Promise((r) => setTimeout(r, delay));
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

        const body = await readLimitedBody(response);
        if (!response.ok) {
          const error = new Error(`OpenAI API ${response.status}`);
          if (isTransientStatus(response.status) && attempt < MAX_RETRIES) {
            lastError = error;
            delay = retryDelay(response);
            continue;
          }
          throw error;
        }

        const data = JSON.parse(body) as ChatCompletionResponse;
        return data.choices[0]?.message?.content || "";
      } catch (err) {
        lastError = err;
        const transientNetworkError = err instanceof TypeError || (err instanceof DOMException && err.name === "AbortError");
        if (!transientNetworkError || attempt === MAX_RETRIES) throw err;
        delay = RETRY_DELAY_MS;
      } finally {
        clearTimeout(timer);
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
