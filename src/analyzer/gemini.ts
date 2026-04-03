import { GoogleGenerativeAI } from "@google/generative-ai";
import type { Endpoint, Vulnerability, AttackPayload, LLMProvider } from "../types.js";
import { buildAnalysisPrompt, buildPayloadPrompt, parseVulnerabilities, parsePayloads } from "./prompts.js";

const DEFAULT_GEMINI_MODEL = "gemini-2.5-flash";
const GEMINI_TIMEOUT_MS = 60000;
const GEMINI_MAX_RETRIES = 2;
const GEMINI_RETRY_DELAY_MS = 1000;

export class GeminiProvider implements LLMProvider {
  private model;

  constructor(modelName?: string) {
    const apiKey = process.env.GEMINI_API_KEY;
    if (!apiKey) {
      throw new Error("GEMINI_API_KEY environment variable is required");
    }
    const genAI = new GoogleGenerativeAI(apiKey);
    this.model = genAI.getGenerativeModel({ model: modelName ?? DEFAULT_GEMINI_MODEL });
  }

  private async withRetryAndTimeout<T>(fn: () => Promise<T>): Promise<T> {
    let lastError: unknown;
    for (let attempt = 0; attempt <= GEMINI_MAX_RETRIES; attempt++) {
      if (attempt > 0) {
        await new Promise((resolve) => setTimeout(resolve, GEMINI_RETRY_DELAY_MS));
      }
      try {
        let timer: ReturnType<typeof setTimeout>;
        const timeoutPromise = new Promise<never>((_, reject) => {
          timer = setTimeout(() => reject(new Error(`Gemini request timed out after ${GEMINI_TIMEOUT_MS}ms`)), GEMINI_TIMEOUT_MS);
        });
        try {
          return await Promise.race([fn(), timeoutPromise]);
        } finally {
          clearTimeout(timer!);
        }
      } catch (err) {
        lastError = err;
      }
    }
    throw lastError;
  }

  async analyze(endpoint: Endpoint): Promise<Vulnerability[]> {
    const result = await this.withRetryAndTimeout(() =>
      this.model.generateContent(buildAnalysisPrompt(endpoint))
    );
    const text = result.response.text();
    return parseVulnerabilities(text, endpoint.url);
  }

  async generatePayloads(endpoint: Endpoint, vulnerabilities: Vulnerability[]): Promise<AttackPayload[]> {
    const result = await this.withRetryAndTimeout(() =>
      this.model.generateContent(buildPayloadPrompt(endpoint, vulnerabilities))
    );
    const text = result.response.text();
    return parsePayloads(text);
  }
}
