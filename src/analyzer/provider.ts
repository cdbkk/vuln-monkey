import type { LLMProvider } from "../types.js";
import { ClaudeProvider } from "./claude.js";
import { GeminiProvider } from "./gemini.js";
import { CLIProvider } from "./cli-provider.js";
import { OpenAICompatProvider } from "./openai-compat.js";

export const VALID_MODELS = new Set([
  "claude", "gemini", "openai", "ollama", "local",
  "claude-cli", "gemini-cli", "codex-cli",
]);

function configuredBaseUrl(defaultUrl: string): string {
  const value = process.env.OPENAI_BASE_URL || process.env.OPENAI_API_BASE;
  if (!value) return defaultUrl;
  try {
    const url = new URL(value);
    if (url.protocol === "http:" || url.protocol === "https:") return value;
  } catch {}
  throw new Error("OPENAI_BASE_URL/OPENAI_API_BASE must be a valid http(s) URL");
}

function createLocalProvider(defaultUrl: string, modelName?: string): LLMProvider {
  const previousBaseUrl = process.env.OPENAI_BASE_URL;
  process.env.OPENAI_BASE_URL = configuredBaseUrl(defaultUrl);
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
      return createLocalProvider("http://localhost:11434/v1", modelName || process.env.OPENAI_MODEL || "llama3.1");
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
