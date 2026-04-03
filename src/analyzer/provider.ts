import type { LLMProvider } from "../types.js";
import { ClaudeProvider } from "./claude.js";
import { GeminiProvider } from "./gemini.js";
import { CLIProvider } from "./cli-provider.js";

export const VALID_MODELS = new Set([
  "claude", "gemini",
  "claude-cli", "gemini-cli", "codex-cli",
]);

export function createProvider(model: string, modelName?: string): LLMProvider {
  switch (model) {
    case "claude":
      return new ClaudeProvider(modelName);
    case "gemini":
      return new GeminiProvider(modelName);
    case "claude-cli":
    case "gemini-cli":
    case "codex-cli":
      return new CLIProvider(model);
    default:
      throw new Error(`Unknown model: ${model}`);
  }
}
