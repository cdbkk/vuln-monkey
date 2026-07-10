import { describe, it, expect, vi } from "vitest";
import { classifyResponse, executePayloads } from "../../src/executor/runner.js";

describe("classifyResponse", () => {
  it("does not treat a benign 2xx as a vulnerability", () => {
    expect(classifyResponse(200, "ok")).toBe("pass");
  });

  it("flags a successful request that should have been rejected", () => {
    expect(classifyResponse(200, "ok", true)).toBe("suspicious");
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

describe("executePayloads", () => {
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
      headers: { "Proxy-Authorization": "secret" },
    };

    const results = await executePayloads([payload], { concurrency: 1, timeout: 5000 }, onResult);

    expect(results).toHaveLength(1);
    expect(results[0].classification).toBe("unverified");
    expect(results[0].responseBody).toContain("URL not allowed");
    expect(results[0].payload.headers["Proxy-Authorization"]).toBe("[REDACTED]");
    expect(onResult).toHaveBeenCalledOnce();
  });

  it("blocks payloads outside the endpoint origin", async () => {
    const onResult = vi.fn();
    const payload = {
      name: "redirected-test",
      method: "GET" as const,
      url: "https://8.8.8.8/test",
      vulnerability: "test",
      headers: {},
    };
    const endpoint = {
      method: "GET" as const,
      url: "https://1.1.1.1/api",
      headers: {},
      auth: { type: "none" as const },
    };

    const results = await executePayloads(
      [payload],
      { concurrency: 1, timeout: 5000, endpoint },
      onResult
    );

    expect(results[0].classification).toBe("unverified");
    expect(results[0].responseBody).toMatch(/cross-origin/i);
    expect(onResult).toHaveBeenCalledOnce();
  });

  it("does not re-add endpoint credentials to no-auth probes", async () => {
    const payload = {
      name: "no-auth",
      method: "GET" as const,
      url: "http://127.0.0.1/test",
      vulnerability: "auth bypass",
      headers: {},
      omitAuth: true,
    };
    const endpoint = {
      method: "GET" as const,
      url: "http://127.0.0.1/test",
      headers: { Authorization: "Bearer real-secret", Cookie: "session=secret" },
      auth: { type: "bearer" as const, value: "real-secret" },
    };

    const [result] = await executePayloads(
      [payload],
      { concurrency: 1, timeout: 100, endpoint },
      vi.fn()
    );

    expect(result.payload.headers).not.toHaveProperty("Authorization");
    expect(result.payload.headers).not.toHaveProperty("Cookie");
  });

  it("removes custom API-key credentials from no-auth probes", async () => {
    const payload = {
      name: "no-auth",
      method: "GET" as const,
      url: "http://127.0.0.1/test",
      vulnerability: "auth bypass",
      headers: {
        "X-Custom-Key": "model-copied-secret",
        "X-Second-Key": "second-secret",
      },
      omitAuth: true,
    };
    const endpoint = {
      method: "GET" as const,
      url: "http://127.0.0.1/test",
      headers: {
        "X-Custom-Key": "real-secret",
        "X-Second-Key": "second-secret",
      },
      auth: { type: "apikey" as const, headerName: "X-Custom-Key", value: "real-secret" },
      credentialHeaderNames: ["X-Custom-Key", "X-Second-Key"],
    };

    const [result] = await executePayloads(
      [payload],
      { concurrency: 1, timeout: 100, endpoint },
      vi.fn()
    );

    expect(result.payload.headers).not.toHaveProperty("X-Custom-Key");
    expect(result.payload.headers).not.toHaveProperty("X-Second-Key");
  });
});
