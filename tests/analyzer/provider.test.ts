import { afterEach, describe, expect, it } from "vitest";
import { createProvider } from "../../src/analyzer/provider.js";

describe("createProvider", () => {
  afterEach(() => {
    delete process.env.OPENAI_MODEL;
    delete process.env.OPENAI_BASE_URL;
    delete process.env.OPENAI_API_BASE;
  });

  it("lets OPENAI_MODEL override the Ollama default", () => {
    process.env.OPENAI_MODEL = "qwen3:8b";
    const provider = createProvider("ollama") as unknown as { model: string };
    expect(provider.model).toBe("qwen3:8b");
  });

  it("keeps an explicit Ollama model above the environment", () => {
    process.env.OPENAI_MODEL = "qwen3:8b";
    const provider = createProvider("ollama", "llama3.2") as unknown as { model: string };
    expect(provider.model).toBe("llama3.2");
  });

  it("uses an explicitly configured LAN Ollama URL", () => {
    process.env.OPENAI_BASE_URL = "http://192.168.1.20:11434/v1";
    const provider = createProvider("ollama") as unknown as { baseUrl: string };
    expect(provider.baseUrl).toBe("http://192.168.1.20:11434/v1");
  });

  it("rejects invalid local provider URLs instead of silently falling back", () => {
    process.env.OPENAI_BASE_URL = "file:///tmp/ollama.sock";
    expect(() => createProvider("ollama")).toThrow("must be a valid http(s) URL");
  });
});
