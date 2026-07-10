import { describe, it, expect } from "vitest";
import { parseOpenAPIFromJSON } from "../../src/parser/openapi.js";
import { AttackPayloadSchema, EndpointSchema } from "../../src/types.js";
import spec from "../fixtures/petstore.json";

describe("parseOpenAPIFromJSON", () => {
  it("extracts all endpoints", () => {
    const endpoints = parseOpenAPIFromJSON(spec);
    expect(endpoints).toHaveLength(4);
  });

  it("sets correct methods", () => {
    const endpoints = parseOpenAPIFromJSON(spec);
    const methods = endpoints.map((e) => e.method).sort();
    expect(methods).toEqual(["DELETE", "GET", "GET", "POST"]);
  });

  it("builds full URLs from server + path", () => {
    const endpoints = parseOpenAPIFromJSON(spec);
    const urls = endpoints.map((e) => e.url).sort();
    expect(urls).toContain("https://api.example.com/users");
    // path params are substituted with a concrete value so the fuzzed URL hits a real route
    expect(urls).toContain("https://api.example.com/users/1");
  });

  it("captures body schema on POST", () => {
    const endpoints = parseOpenAPIFromJSON(spec);
    const post = endpoints.find((e) => e.method === "POST");
    expect(post?.bodySchema).toBeDefined();
    expect((post?.bodySchema as any).properties).toHaveProperty("name");
    expect((post?.bodySchema as any).properties).toHaveProperty("email");
  });

  it("throws on missing servers array", () => {
    expect(() => parseOpenAPIFromJSON({ openapi: "3.0.0", paths: {} })).toThrow("no servers");
  });

  it("strips trailing slash from server URL", () => {
    const endpoints = parseOpenAPIFromJSON({
      openapi: "3.0.0",
      servers: [{ url: "https://api.example.com/" }],
      paths: {
        "/test": {
          get: { responses: { "200": { description: "ok" } } },
        },
      },
    });
    expect(endpoints[0].url).toBe("https://api.example.com/test");
  });

  it("returns empty array for spec with no paths", () => {
    const endpoints = parseOpenAPIFromJSON({
      openapi: "3.0.0",
      servers: [{ url: "https://api.example.com" }],
      paths: {},
    });
    expect(endpoints).toHaveLength(0);
  });

  it("uses operation, path, then root server precedence", () => {
    const endpoints = parseOpenAPIFromJSON({
      openapi: "3.0.0",
      servers: [{ url: "https://root.example.com" }],
      paths: {
        "/operation": {
          servers: [{ url: "https://path.example.com" }],
          get: {
            servers: [{ url: "https://operation.example.com" }],
            responses: { "200": { description: "ok" } },
          },
          post: { responses: { "200": { description: "ok" } } },
        },
        "/root": {
          put: { responses: { "200": { description: "ok" } } },
        },
      },
    });

    expect(endpoints.map(({ method, url }) => [method, url])).toEqual([
      ["GET", "https://operation.example.com/operation"],
      ["POST", "https://path.example.com/operation"],
      ["PUT", "https://root.example.com/root"],
    ]);
  });

  it("substitutes server variable defaults", () => {
    const endpoints = parseOpenAPIFromJSON({
      openapi: "3.0.0",
      servers: [{
        url: "https://{tenant}.example.com/{version}",
        variables: {
          tenant: { default: "demo" },
          version: { default: "v2" },
        },
      }],
      paths: {
        "/users": { get: { responses: { "200": { description: "ok" } } } },
      },
    });

    expect(endpoints[0].url).toBe("https://demo.example.com/v2/users");
  });

  it("extracts HEAD and OPTIONS operations", () => {
    const endpoints = parseOpenAPIFromJSON({
      openapi: "3.0.0",
      servers: [{ url: "https://api.example.com" }],
      paths: {
        "/health": {
          head: { responses: { "200": { description: "ok" } } },
          options: { responses: { "204": { description: "ok" } } },
        },
      },
    });

    expect(endpoints.map(({ method }) => method)).toEqual(["HEAD", "OPTIONS"]);
    expect(EndpointSchema.parse(endpoints[0]).method).toBe("HEAD");
    expect(AttackPayloadSchema.parse({
      name: "CORS preflight",
      vulnerability: "cors",
      method: "OPTIONS",
      url: endpoints[1].url,
      headers: {},
    }).method).toBe("OPTIONS");
  });

  it("marks protected operations without inventing credentials", () => {
    const endpoints = parseOpenAPIFromJSON({
      openapi: "3.0.0",
      servers: [{ url: "https://api.example.com" }],
      security: [{ BearerAuth: [] }],
      components: {
        securitySchemes: {
          BearerAuth: { type: "http", scheme: "bearer" },
        },
      },
      paths: {
        "/private": { get: { responses: { "200": { description: "ok" } } } },
      },
    });

    expect(endpoints[0].auth).toEqual({ type: "bearer" });
    expect(endpoints[0].headers).toEqual({});
  });

  it("applies every credential in an AND security requirement", () => {
    const endpoints = parseOpenAPIFromJSON({
      openapi: "3.0.0",
      servers: [{ url: "https://api.example.com" }],
      security: [{ BearerAuth: [], ApiKeyAuth: [], SessionAuth: [] }],
      components: {
        securitySchemes: {
          BearerAuth: { type: "http", scheme: "bearer" },
          ApiKeyAuth: { type: "apiKey", in: "header", name: "X-API-Key" },
          SessionAuth: { type: "apiKey", in: "cookie", name: "session" },
        },
      },
      paths: {
        "/private": { get: { responses: { "200": { description: "ok" } } } },
      },
    }, undefined, {
      authorization: "Bearer real-token",
      "x-api-key": "real-key",
      cookie: "session=real-session; unrelated=value",
    }, ["https://api.example.com"]);

    expect(endpoints[0].headers).toEqual({
      Authorization: "Bearer real-token",
      "X-API-Key": "real-key",
      Cookie: "session=real-session",
    });
    expect(endpoints[0].credentialHeaderNames).toEqual([
      "Authorization",
      "X-API-Key",
      "Cookie",
    ]);
  });

  it("selects the first satisfiable OR security requirement", () => {
    const endpoints = parseOpenAPIFromJSON({
      openapi: "3.0.0",
      servers: [{ url: "https://api.example.com" }],
      security: [
        { ApiKeyAuth: [] },
        { BearerAuth: [] },
      ],
      components: {
        securitySchemes: {
          ApiKeyAuth: { type: "apiKey", in: "header", name: "X-API-Key" },
          BearerAuth: { type: "http", scheme: "bearer" },
        },
      },
      paths: {
        "/private": { get: { responses: { "200": { description: "ok" } } } },
      },
    }, undefined, { Authorization: "Bearer real-token" }, ["https://api.example.com"]);

    expect(endpoints[0].auth).toEqual({ type: "bearer", value: "real-token" });
    expect(endpoints[0].headers).toEqual({ Authorization: "Bearer real-token" });
  });

  it("does not send credentials to an untrusted operation server", () => {
    const endpoints = parseOpenAPIFromJSON({
      openapi: "3.0.0",
      servers: [{ url: "https://api.example.com" }],
      security: [{ BearerAuth: [] }],
      components: {
        securitySchemes: {
          BearerAuth: { type: "http", scheme: "bearer" },
        },
      },
      paths: {
        "/private": {
          get: {
            servers: [{ url: "https://attacker.example" }],
            responses: { "200": { description: "ok" } },
          },
        },
      },
    }, undefined, {
      Authorization: "Bearer real-token",
    }, ["https://api.example.com"]);

    expect(endpoints[0].url).toBe("https://attacker.example/private");
    expect(endpoints[0].headers).not.toHaveProperty("Authorization");
    expect(endpoints[0].auth).toEqual({ type: "bearer" });
  });

  it("lets operation parameters override matching path parameters", () => {
    const [endpoint] = parseOpenAPIFromJSON({
      openapi: "3.0.0",
      servers: [{ url: "https://api.example.com" }],
      paths: {
        "/search": {
          parameters: [{ name: "q", in: "query", required: true, example: "path" }],
          get: {
            parameters: [{ name: "q", in: "query", required: true, example: "operation" }],
          },
        },
      },
    });

    expect(endpoint.url).toBe("https://api.example.com/search?q=operation");
  });

  it("preserves non-JSON request content types", () => {
    const [endpoint] = parseOpenAPIFromJSON({
      openapi: "3.0.0",
      servers: [{ url: "https://api.example.com" }],
      paths: {
        "/form": {
          post: {
            requestBody: {
              content: {
                "application/x-www-form-urlencoded": {
                  schema: { type: "object" },
                  example: { name: "Connor McLeod" },
                },
              },
            },
          },
        },
      },
    });

    expect(endpoint.headers["Content-Type"]).toBe("application/x-www-form-urlencoded");
    expect(endpoint.body).toEqual({ name: "Connor McLeod" });
  });
});
