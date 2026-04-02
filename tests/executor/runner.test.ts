import { describe, it, expect } from "vitest";
import { classifyResponse } from "../../src/executor/runner.js";

describe("classifyResponse", () => {
  it("marks 2xx with reflected payload as suspicious", () => {
    expect(classifyResponse(200, '{"admin":true,"role":"admin"}', {})).toBe("suspicious");
  });

  it("marks 5xx as crash", () => {
    expect(classifyResponse(500, "Internal Server Error", {})).toBe("crash");
  });

  it("marks 4xx with stack trace as error", () => {
    expect(classifyResponse(400, "Error at handler.js:42:15\n    at process.js:10:3", {})).toBe("error");
  });

  it("marks clean 4xx as pass", () => {
    expect(classifyResponse(400, '{"error":"Bad Request"}', {})).toBe("pass");
  });

  it("marks 401 as pass", () => {
    expect(classifyResponse(401, "Unauthorized", {})).toBe("pass");
  });

  it("marks 403 as pass", () => {
    expect(classifyResponse(403, "Forbidden", {})).toBe("pass");
  });
});
