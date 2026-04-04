import { describe, it, expect } from "vitest";
import { synthesizeFallbackPayloads } from "../../src/analyzer/fallback.js";
import type { Endpoint, Vulnerability } from "../../src/types.js";

const POST_WITH_AUTH: Endpoint = {
  method: "POST",
  url: "https://api.example.com/users/123",
  headers: { "Content-Type": "application/json", Authorization: "Bearer abc" },
  body: { name: "test" },
  auth: { type: "bearer", value: "abc" },
};

const GET_NO_AUTH: Endpoint = {
  method: "GET",
  url: "https://api.example.com/public",
  headers: {},
  auth: { type: "none" },
};

const MINIMAL_SCHEMA_POST: Endpoint = {
  method: "POST",
  url: "https://jlymrjqotpluplvnvxeb.supabase.co/functions/v1/send-parent-email-reminder",
  headers: { "Content-Type": "application/json" },
  body: { dryRun: true },
  auth: { type: "none" },
};

describe("synthesizeFallbackPayloads", () => {
  it("never returns an empty array for a POST endpoint", () => {
    const payloads = synthesizeFallbackPayloads(POST_WITH_AUTH, []);
    expect(payloads.length).toBeGreaterThanOrEqual(8);
  });

  it("never returns an empty array for a GET endpoint", () => {
    const payloads = synthesizeFallbackPayloads(GET_NO_AUTH, []);
    expect(payloads.length).toBeGreaterThanOrEqual(4);
  });

  it("never returns empty for minimal body schemas (the regression case)", () => {
    const payloads = synthesizeFallbackPayloads(MINIMAL_SCHEMA_POST, []);
    expect(payloads.length).toBeGreaterThanOrEqual(8);
  });

  it("includes a no-credentials probe as the first payload", () => {
    const payloads = synthesizeFallbackPayloads(POST_WITH_AUTH, []);
    const noAuth = payloads[0];
    expect(noAuth.vulnerability).toBe("auth bypass");
    expect(noAuth.headers.Authorization).toBeUndefined();
  });

  it("strips Authorization, X-API-Key, apikey, api-key headers in no-auth probe", () => {
    const endpoint: Endpoint = {
      ...POST_WITH_AUTH,
      headers: {
        "Content-Type": "application/json",
        Authorization: "Bearer abc",
        "X-API-Key": "key1",
        apikey: "key2",
        "api-key": "key3",
      },
    };
    const payloads = synthesizeFallbackPayloads(endpoint, []);
    const noAuth = payloads.find((p) => p.name.includes("No Credentials"));
    expect(noAuth).toBeDefined();
    expect(noAuth!.headers.Authorization).toBeUndefined();
    expect(noAuth!.headers["X-API-Key"]).toBeUndefined();
    expect(noAuth!.headers.apikey).toBeUndefined();
    expect(noAuth!.headers["api-key"]).toBeUndefined();
    expect(noAuth!.headers["Content-Type"]).toBe("application/json");
  });

  it("includes invalid-token probe only when endpoint has auth", () => {
    const withAuth = synthesizeFallbackPayloads(POST_WITH_AUTH, []);
    const withoutAuth = synthesizeFallbackPayloads(GET_NO_AUTH, []);
    expect(withAuth.some((p) => p.name.includes("Invalid Token"))).toBe(true);
    expect(withoutAuth.some((p) => p.name.includes("Invalid Token"))).toBe(false);
  });

  it("injects privilege escalation fields into mass assignment probe", () => {
    const payloads = synthesizeFallbackPayloads(POST_WITH_AUTH, []);
    const massAssign = payloads.find((p) => p.name.includes("Privilege Fields"));
    expect(massAssign).toBeDefined();
    const body = massAssign!.body as Record<string, unknown>;
    expect(body.isAdmin).toBe(true);
    expect(body.role).toBe("admin");
    expect(body.is_superuser).toBe(true);
    // Preserves original fields
    expect(body.name).toBe("test");
  });

  it("swaps HTTP method in the method-override probe", () => {
    const post = synthesizeFallbackPayloads(POST_WITH_AUTH, []);
    const swap = post.find((p) => p.name.includes("Method Override"));
    expect(swap).toBeDefined();
    expect(swap!.method).toBe("GET");

    const get = synthesizeFallbackPayloads(GET_NO_AUTH, []);
    const swapGet = get.find((p) => p.name.includes("Method Override"));
    expect(swapGet).toBeDefined();
    expect(swapGet!.method).toBe("POST");
  });

  it("produces a path-traversal probe with URL-encoded traversal", () => {
    // We use %2E (encoded dot) instead of raw ../../ because URL.pathname
    // normalizes raw traversal segments away before the request fires.
    // Encoded traversal survives normalization and is the real-world bypass
    // against servers that decode percent-encoding after path normalization.
    const payloads = synthesizeFallbackPayloads(POST_WITH_AUTH, []);
    const traversal = payloads.find((p) => p.name.includes("Path Traversal"));
    expect(traversal).toBeDefined();
    expect(traversal!.url).toContain("%2E%2E");
    expect(traversal!.url).toContain("etc/passwd");
  });

  it("skips body-dependent probes for GET endpoints", () => {
    const payloads = synthesizeFallbackPayloads(GET_NO_AUTH, []);
    // No empty-body, no malformed JSON, no oversized body on a GET
    expect(payloads.some((p) => p.name.includes("Empty Body"))).toBe(false);
    expect(payloads.some((p) => p.name.includes("Malformed JSON"))).toBe(false);
    expect(payloads.some((p) => p.name.includes("Large Payload"))).toBe(false);
  });

  it("tags payloads with LLM-identified vuln types when provided", () => {
    const vulns: Vulnerability[] = [
      {
        type: "auth bypass",
        description: "public endpoint",
        severity: "critical",
        endpoint: POST_WITH_AUTH.url,
      },
      {
        type: "IDOR",
        description: "user id in body",
        severity: "high",
        endpoint: POST_WITH_AUTH.url,
      },
    ];
    const payloads = synthesizeFallbackPayloads(POST_WITH_AUTH, vulns);
    for (const p of payloads) {
      expect(p.name).toContain("LLM-identified: auth bypass, IDOR");
    }
  });

  it("handles endpoints with invalid URL gracefully (skips path traversal)", () => {
    const bad: Endpoint = {
      method: "POST",
      url: "not a url",
      headers: {},
      body: {},
      auth: { type: "none" },
    };
    // Should not throw; should still produce other probes
    const payloads = synthesizeFallbackPayloads(bad, []);
    expect(payloads.length).toBeGreaterThan(0);
    // Path traversal probe should be absent because URL parse failed
    expect(payloads.some((p) => p.name.includes("Path Traversal"))).toBe(false);
  });

  it("oversized body probe contains a large string", () => {
    const payloads = synthesizeFallbackPayloads(POST_WITH_AUTH, []);
    const overflow = payloads.find((p) => p.name.includes("Large Payload"));
    expect(overflow).toBeDefined();
    const body = overflow!.body as Record<string, unknown>;
    expect(typeof body.overflow_probe).toBe("string");
    expect((body.overflow_probe as string).length).toBe(10_000);
  });
});
