import { describe, it, expect } from "vitest";
import { parseOpenAPIFromJSON } from "../../src/parser/openapi.js";
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
    expect(urls).toContain("https://api.example.com/users/{id}");
  });

  it("captures body schema on POST", () => {
    const endpoints = parseOpenAPIFromJSON(spec);
    const post = endpoints.find((e) => e.method === "POST");
    expect(post?.bodySchema).toBeDefined();
    expect((post?.bodySchema as any).properties).toHaveProperty("name");
    expect((post?.bodySchema as any).properties).toHaveProperty("email");
  });
});
