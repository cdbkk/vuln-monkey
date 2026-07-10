import { beforeEach, describe, expect, it, vi } from "vitest";
import { EventEmitter } from "node:events";
import type { ClientRequest, IncomingMessage } from "node:http";

const mocks = vi.hoisted(() => ({
  resolve: vi.fn(),
  request: vi.fn(),
}));

vi.mock("node:dns/promises", () => ({
  resolve: mocks.resolve,
}));

vi.mock("node:http", async (importOriginal) => ({
  ...await importOriginal<typeof import("node:http")>(),
  request: mocks.request,
}));

import { readPublicUrl, requestPublicUrl } from "../../src/executor/public-http.js";

function mockHttpResponse(headers: Record<string, string> = {}, body = "ok") {
  const write = vi.fn();
  mocks.request.mockImplementation((_url, _options, callback) => {
    const request = new EventEmitter() as unknown as ClientRequest;
    request.write = write;
    request.end = vi.fn(() => queueMicrotask(() => {
      const response = Object.assign(new EventEmitter(), {
        statusCode: 200,
        headers,
        destroy: vi.fn(),
      }) as unknown as IncomingMessage;
      callback(response);
      queueMicrotask(() => {
        response.emit("data", Buffer.from(body));
        response.emit("end");
      });
    }));
    return request;
  });
  return write;
}

describe("readPublicUrl", () => {
  beforeEach(() => {
    mocks.resolve.mockReset();
    mocks.request.mockReset();
  });

  it.each([
    "http://10.0.0.1",
    "http://100.64.0.1",
    "http://127.0.0.1",
    "http://169.254.169.254",
    "http://172.16.0.1",
    "http://192.168.0.1",
    "http://198.18.0.1",
    "http://224.0.0.1",
    "http://240.0.0.1",
    "http://[::1]",
    "http://[::ffff:127.0.0.1]",
    "http://[3fff::1]",
    "http://[5f00::1]",
    "http://[fc00::1]",
    "http://[fe80::1]",
    "http://[fec0::1]",
    "http://[ff00::1]",
  ])("blocks non-global address %s", async (url) => {
    await expect(readPublicUrl(url, 100)).rejects.toThrow("URL not allowed");
  });

  it("blocks a hostname when any DNS answer is non-global", async () => {
    mocks.resolve.mockImplementation((_hostname: string, recordType: string) =>
      recordType === "A"
        ? Promise.resolve(["8.8.8.8", "100.64.0.1"])
        : Promise.reject(new Error("no AAAA record"))
    );

    await expect(readPublicUrl("https://example.com", 100)).rejects.toThrow("URL not allowed");
  });

  it("allows private targets only with explicit opt-in", async () => {
    mockHttpResponse();

    await expect(requestPublicUrl("http://127.0.0.1", {
      method: "GET",
      headers: {},
      timeout: 100,
      allowPrivate: true,
    })).resolves.toMatchObject({ statusCode: 200, body: "ok" });
  });

  it("returns pinned addresses in Node's all-address lookup shape", async () => {
    mocks.resolve.mockResolvedValue(["8.8.8.8"]);
    mockHttpResponse();

    await requestPublicUrl("http://example.com", {
      method: "GET",
      headers: {},
      timeout: 100,
    });

    const lookup = mocks.request.mock.calls[0][1].lookup;
    const addresses = await new Promise((resolve, reject) => {
      lookup("example.com", { all: true }, (error: Error | null, result: unknown) => {
        if (error) reject(error);
        else resolve(result);
      });
    });
    expect(addresses).toEqual([{ address: "8.8.8.8", family: 4 }]);
  });

  it("applies the timeout while resolving DNS", async () => {
    mocks.resolve.mockImplementation(() => new Promise(() => {}));
    const start = Date.now();

    await expect(readPublicUrl("https://example.com", 20)).rejects.toThrow("timed out");
    expect(Date.now() - start).toBeLessThan(500);
  });

  it("falls back to the next validated address", async () => {
    mocks.resolve.mockResolvedValue(["8.8.8.8", "1.1.1.1"]);
    mocks.request.mockImplementation((_url, _options, callback) => {
      const request = new EventEmitter() as unknown as ClientRequest;
      request.write = vi.fn();
      request.end = vi.fn(() => queueMicrotask(() => {
        if (mocks.request.mock.calls.length === 1) {
          request.emit("error", new Error("connection failed"));
          return;
        }

        const response = Object.assign(new EventEmitter(), {
          statusCode: 200,
          headers: {},
          destroy: vi.fn(),
        }) as unknown as IncomingMessage;
        callback(response);
        queueMicrotask(() => {
          response.emit("data", Buffer.from("ok"));
          response.emit("end");
        });
      }));
      return request;
    });

    await expect(readPublicUrl("http://example.com", 100)).resolves.toBe("ok");
    expect(mocks.request).toHaveBeenCalledTimes(2);
  });

  it("follows bounded redirects through the same safety checks", async () => {
    mocks.resolve.mockResolvedValue(["8.8.8.8"]);
    mocks.request.mockImplementation((_url, _options, callback) => {
      const request = new EventEmitter() as unknown as ClientRequest;
      request.write = vi.fn();
      request.end = vi.fn(() => queueMicrotask(() => {
        const redirected = mocks.request.mock.calls.length === 1;
        const response = Object.assign(new EventEmitter(), {
          statusCode: redirected ? 302 : 200,
          headers: redirected ? { location: "/openapi.json" } : {},
          destroy: vi.fn(),
        }) as unknown as IncomingMessage;
        callback(response);
        queueMicrotask(() => {
          response.emit("data", Buffer.from(redirected ? "" : "ok"));
          response.emit("end");
        });
      }));
      return request;
    });

    await expect(readPublicUrl("http://example.com/start", 100)).resolves.toBe("ok");
    expect(mocks.request).toHaveBeenCalledTimes(2);
  });

  it("keeps the 10 MiB spec limit separate from the payload limit", async () => {
    mocks.resolve.mockResolvedValue(["8.8.8.8"]);
    mockHttpResponse({ "content-length": String(2 * 1024 * 1024) });

    await expect(readPublicUrl("http://example.com", 100)).resolves.toBe("ok");

    const payloadResponse = await requestPublicUrl("http://example.com", {
      method: "GET",
      headers: {},
      timeout: 100,
    });
    expect(payloadResponse.tooLarge).toBe(true);
  });

  it("does not send a body with HEAD", async () => {
    mocks.resolve.mockResolvedValue(["8.8.8.8"]);
    const write = mockHttpResponse();

    await requestPublicUrl("http://example.com", {
      method: "HEAD",
      headers: {},
      body: "must not be sent",
      timeout: 100,
    });

    expect(write).not.toHaveBeenCalled();
  });

  it("serializes form bodies according to their content type", async () => {
    mocks.resolve.mockResolvedValue(["8.8.8.8"]);
    const write = mockHttpResponse();

    await requestPublicUrl("http://example.com", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: { name: "Connor McLeod", role: "user" },
      timeout: 100,
    });

    expect(write).toHaveBeenCalledWith("name=Connor+McLeod&role=user");
  });
});
