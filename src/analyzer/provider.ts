import type { LLMProvider } from "../types.js";
import { ClaudeProvider } from "./claude.js";
import { GeminiProvider } from "./gemini.js";

export function createProvider(model: "claude" | "gemini", modelName?: string): LLMProvider {
  if (model === "gemini") return new GeminiProvider(modelName);
  return new ClaudeProvider(modelName);
}
