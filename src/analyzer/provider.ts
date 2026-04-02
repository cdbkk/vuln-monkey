import type { LLMProvider } from "../types.js";
import { ClaudeProvider } from "./claude.js";
import { GeminiProvider } from "./gemini.js";

export function createProvider(model: "claude" | "gemini"): LLMProvider {
  if (model === "gemini") return new GeminiProvider();
  return new ClaudeProvider();
}
