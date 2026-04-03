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

  it("handles backslash-escaped quotes in body", () => {
    const result = parseCurl(String.raw`curl -X POST https://api.example.com/data -d "{\"key\":\"value\"}"`);;
    expect(result.method).toBe("POST");
    expect(result.url).toBe("https://api.example.com/data");
    expect(result.body).toEqual({ key: "value" });
  });

  it("handles backslash-newline continuation", () => {
    const result = parseCurl("curl https://api.example.com/users \\\n  -H 'Accept: application/json'");
    expect(result.method).toBe("GET");
    expect(result.url).toBe("https://api.example.com/users");
    expect(result.headers["accept"]).toBe("application/json");
  });

  it("handles --compressed and other unknown flags", () => {
    const result = parseCurl("curl --compressed -s https://api.example.com/data");
    expect(result.method).toBe("GET");
    expect(result.url).toBe("https://api.example.com/data");
  });

  it("extracts basic auth", () => {
    const result = parseCurl("curl -H 'Authorization: Basic dXNlcjpwYXNz' https://api.example.com/me");
    expect(result.auth.type).toBe("basic");
    expect(result.auth.value).toBe("dXNlcjpwYXNz");
  });

  it("auto-upgrades GET to POST with -d", () => {
    const result = parseCurl("curl https://api.example.com/data -d 'test'");
    expect(result.method).toBe("POST");
  });

  it("preserves URL with query string", () => {
    const result = parseCurl("curl 'https://api.example.com/search?q=foo&page=2'");
    expect(result.url).toContain("?q=foo&page=2");
  });

  it("throws on unsupported HTTP method", () => {
    expect(() => parseCurl("curl -X CONNECT https://api.example.com")).toThrow("Unsupported HTTP method");
  });

  it("handles -X at end without value gracefully", () => {
    // Parser breaks out of loop when -X has no following token, URL is still found
    const result = parseCurl("curl https://api.example.com -X");
    expect(result.url).toBe("https://api.example.com");
  });
});
