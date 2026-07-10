import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Endpoint } from "../../src/types.js";
import { OpenAICompatProvider } from "../../src/analyzer/openai-compat.js";

const ENDPOINT: Endpoint = {
  method: "GET",
  url: "https://api.example.com/users",
  headers: {},
  auth: { type: "none" },
};

describe("OpenAICompatProvider", () => {
  beforeEach(() => {
    process.env.OPENAI_BASE_URL = "http://localhost:1234/v1";
  });

  afterEach(() => {
    delete process.env.OPENAI_BASE_URL;
    delete process.env.OPENAI_API_KEY;
    vi.unstubAllGlobals();
  });

  it("sends an explicitly configured key to compatible endpoints", async () => {
    process.env.OPENAI_BASE_URL = "https://compat.example.test/v1";
    process.env.OPENAI_API_KEY = "compat-key";
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ choices: [{ message: { content: "[]" } }] }))
    );
    vi.stubGlobal("fetch", fetchMock);

    await new OpenAICompatProvider().analyze(ENDPOINT);

    expect(fetchMock.mock.calls[0][1].headers.Authorization).toBe("Bearer compat-key");
  });

  it("does not retry permanent HTTP errors", async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response("denied", { status: 401 }));
    vi.stubGlobal("fetch", fetchMock);

    await expect(new OpenAICompatProvider().analyze(ENDPOINT)).rejects.toThrow("OpenAI API 401");
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("rejects oversized responses without retrying", async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response("x".repeat(1024 * 1024 + 1)));
    vi.stubGlobal("fetch", fetchMock);

    await expect(new OpenAICompatProvider().analyze(ENDPOINT)).rejects.toThrow("response exceeds 1048576 bytes");
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("retries transient HTTP errors", async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(new Response("busy", { status: 503, headers: { "Retry-After": "0" } }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ choices: [{ message: { content: "[]" } }] })));
    vi.stubGlobal("fetch", fetchMock);

    await expect(new OpenAICompatProvider().analyze(ENDPOINT)).resolves.toEqual([]);
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });
});
