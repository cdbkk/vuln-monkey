import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Endpoint } from "../../src/types.js";

const { getGenerativeModelMock } = vi.hoisted(() => ({
  getGenerativeModelMock: vi.fn(),
}));

vi.mock("@google/generative-ai", () => ({
  GoogleGenerativeAI: class {
    getGenerativeModel = getGenerativeModelMock;
  },
}));

import { GeminiProvider } from "../../src/analyzer/gemini.js";

const ENDPOINT: Endpoint = {
  method: "GET",
  url: "https://api.example.com/users",
  headers: {},
  auth: { type: "none" },
};

describe("GeminiProvider", () => {
  beforeEach(() => {
    process.env.GEMINI_API_KEY = "test-key";
    vi.useFakeTimers();
  });

  afterEach(() => {
    delete process.env.GEMINI_API_KEY;
    vi.useRealTimers();
    vi.clearAllMocks();
  });

  it("aborts each timed-out request before retrying", async () => {
    const signals: AbortSignal[] = [];
    const generateContent = vi.fn((_prompt, options: { signal: AbortSignal }) => {
      signals.push(options.signal);
      return new Promise((_resolve, reject) => {
        options.signal.addEventListener("abort", () => reject(options.signal.reason), { once: true });
      });
    });
    getGenerativeModelMock.mockReturnValue({ generateContent });

    const assertion = expect(new GeminiProvider().analyze(ENDPOINT)).rejects.toThrow("timed out");
    await vi.advanceTimersByTimeAsync(182_000);
    await assertion;

    expect(generateContent).toHaveBeenCalledTimes(3);
    expect(signals.every((signal) => signal.aborted)).toBe(true);
  });
});
