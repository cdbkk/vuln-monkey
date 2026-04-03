import type { LLMProvider } from "../types.js";
import { ClaudeProvider } from "./claude.js";
import { GeminiProvider } from "./gemini.js";
import { CLIProvider } from "./cli-provider.js";
import { OpenAICompatProvider } from "./openai-compat.js";

export const VALID_MODELS = new Set([
  "claude", "gemini", "openai", "ollama", "local",
  "claude-cli", "gemini-cli", "codex-cli",
]);

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
      if (!process.env.OPENAI_BASE_URL && !process.env.OPENAI_API_BASE) {
        process.env.OPENAI_BASE_URL = "http://localhost:11434/v1";
      }
      return new OpenAICompatProvider(modelName || "llama3.1");
    case "local":
      // Generic local LLM (LM Studio, vLLM, llama.cpp server, etc.)
      if (!process.env.OPENAI_BASE_URL && !process.env.OPENAI_API_BASE) {
        process.env.OPENAI_BASE_URL = "http://localhost:1234/v1";
      }
      return new OpenAICompatProvider(modelName);
    case "claude-cli":
    case "gemini-cli":
    case "codex-cli":
      return new CLIProvider(model);
    default:
      throw new Error(`Unknown model: ${model}`);
  }
}
