import { describe, it, expect } from "vitest";
import { parseCurl } from "../../src/parser/curl.js";

describe("parseCurl", () => {
  it("parses a simple GET", () => {
    const result = parseCurl('curl https://api.example.com/users');
    expect(result.method).toBe("GET");
    expect(result.url).toBe("https://api.example.com/users");
    expect(result.headers).toEqual({});
    expect(result.body).toBeUndefined();
  });

  it("parses POST with headers and body", () => {
    const result = parseCurl(
      `curl -X POST https://api.example.com/users -H 'Content-Type: application/json' -H 'Authorization: Bearer tok123' -d '{"name":"test"}'`
    );
    expect(result.method).toBe("POST");
    expect(result.url).toBe("https://api.example.com/users");
    expect(result.headers["content-type"]).toBe("application/json");
    expect(result.headers["authorization"]).toBe("Bearer tok123");
    expect(result.body).toEqual({ name: "test" });
  });

  it("extracts bearer auth", () => {
    const result = parseCurl(
      `curl -H 'Authorization: Bearer mytoken' https://api.example.com/me`
    );
    expect(result.auth.type).toBe("bearer");
    expect(result.auth.value).toBe("mytoken");
  });

  it("handles double-quoted headers", () => {
    const result = parseCurl(
      `curl -H "Content-Type: application/json" https://api.example.com/test`
    );
    expect(result.headers["content-type"]).toBe("application/json");
  });

  it("handles --data flag", () => {
    const result = parseCurl(
      `curl -X PUT https://api.example.com/item/1 --data '{"price":99}'`
    );
    expect(result.method).toBe("PUT");
    expect(result.body).toEqual({ price: 99 });
  });

  it("throws on missing URL", () => {
    expect(() => parseCurl("curl -X POST")).toThrow();
  });
});
