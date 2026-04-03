import { describe, it, expect, vi, afterEach } from "vitest";
import { classifyResponse, executePayloads } from "../../src/executor/runner.js";

describe("classifyResponse", () => {
  it("marks 2xx with reflected payload as suspicious", () => {
    expect(classifyResponse(200, '{"admin":true,"role":"admin"}')).toBe("suspicious");
  });

  it("marks 5xx as crash", () => {
    expect(classifyResponse(500, "Internal Server Error")).toBe("crash");
  });

  it("marks 4xx with stack trace as error", () => {
    expect(classifyResponse(400, "Error at handler.js:42:15\n    at process.js:10:3")).toBe("error");
  });

  it("marks clean 4xx as pass", () => {
    expect(classifyResponse(400, '{"error":"Bad Request"}')).toBe("pass");
  });

  it("marks 401 as pass", () => {
    expect(classifyResponse(401, "Unauthorized")).toBe("pass");
  });

  it("marks 403 as pass", () => {
    expect(classifyResponse(403, "Forbidden")).toBe("pass");
  });

  it("marks 3xx as pass", () => {
    expect(classifyResponse(301, "Moved")).toBe("pass");
  });

  it("detects Python stack trace", () => {
    expect(classifyResponse(400, 'File "/app/main.py", line 42')).toBe("error");
  });

  it("detects SQL error", () => {
    expect(classifyResponse(400, "SQL syntax error near SELECT")).toBe("error");
  });
});

function makeStreamBody(text: string): ReadableStream<Uint8Array> {
  const encoder = new TextEncoder();
  const bytes = encoder.encode(text);
  return new ReadableStream({
    start(controller) {
      controller.enqueue(bytes);
      controller.close();
    },
  });
}

describe("executePayloads", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("executes payloads and calls onResult callback", async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      status: 200,
      headers: new Headers(),
      body: makeStreamBody("ok"),
    });
    vi.stubGlobal("fetch", mockFetch);

    const onResult = vi.fn();
    const payload = {
      name: "test",
      method: "GET" as const,
      url: "https://api.example.com/test",
      vulnerability: "test",
      headers: {},
    };

    const results = await executePayloads([payload], { concurrency: 1, timeout: 5000 }, onResult);

    expect(results).toHaveLength(1);
    expect(onResult).toHaveBeenCalledOnce();
  });

  it("handles empty payload array", async () => {
    const onResult = vi.fn();
    const results = await executePayloads([], { concurrency: 1, timeout: 5000 }, onResult);
    expect(results).toHaveLength(0);
  });

  it("blocks internal URLs", async () => {
    const onResult = vi.fn();
    const payload = {
      name: "ssrf-test",
      method: "GET" as const,
      url: "http://127.0.0.1/admin",
      vulnerability: "SSRF",
      headers: {},
    };

    const results = await executePayloads([payload], { concurrency: 1, timeout: 5000 }, onResult);

    expect(results).toHaveLength(1);
    expect(results[0].classification).toBe("pass");
    expect(results[0].responseBody).toContain("Blocked");
  });
});
