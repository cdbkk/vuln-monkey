import type { LLMProvider } from "../types.js";
import { ClaudeProvider } from "./claude.js";
import { GeminiProvider } from "./gemini.js";
import { CLIProvider } from "./cli-provider.js";
import { OpenAICompatProvider } from "./openai-compat.js";

export const VALID_MODELS = new Set([
  "claude", "gemini", "openai", "ollama", "local",
  "claude-cli", "gemini-cli", "codex-cli",
]);

function isLocalBaseUrl(value?: string): boolean {
  if (!value) return false;
  try {
    const host = new URL(value).hostname.toLowerCase();
    return host === "localhost" || host.endsWith(".localhost") || host.startsWith("127.") || host === "0.0.0.0" || host === "::1" || host === "[::1]";
  } catch {
    return false;
  }
}

function localBaseUrl(defaultUrl: string): string {
  const baseUrl = process.env.OPENAI_BASE_URL;
  if (baseUrl && isLocalBaseUrl(baseUrl)) return baseUrl;

  const apiBase = process.env.OPENAI_API_BASE;
  if (apiBase && isLocalBaseUrl(apiBase)) return apiBase;

  return defaultUrl;
}

function createLocalProvider(defaultUrl: string, modelName?: string): LLMProvider {
  const previousBaseUrl = process.env.OPENAI_BASE_URL;
  process.env.OPENAI_BASE_URL = localBaseUrl(defaultUrl);
  try {
    return new OpenAICompatProvider(modelName);
  } finally {
    if (previousBaseUrl === undefined) {
      delete process.env.OPENAI_BASE_URL;
    } else {
      process.env.OPENAI_BASE_URL = previousBaseUrl;
    }
  }
}

export function createProvider(model: string, modelName?: string): LLMProvider {
  switch (model) {
    case "claude":
      return new ClaudeProvider(modelName);
    case "gemini":
      return new GeminiProvider(modelName);
    case "openai":
      return new OpenAICompatProvider(modelName);
    case "ollama":
      // Ollama serves an OpenAI-compatible API on localhost:11434
      return createLocalProvider("http://localhost:11434/v1", modelName || "llama3.1");
    case "local":
      // Generic local LLM (LM Studio, vLLM, llama.cpp server, etc.)
      return createLocalProvider("http://localhost:1234/v1", modelName);
    case "claude-cli":
    case "gemini-cli":
    case "codex-cli":
      return new CLIProvider(model);
    default:
      throw new Error(`Unknown model: ${model}`);
  }
}
