import type { AttackPayload, ExecutionResult } from "../types.js";

const STACK_TRACE_PATTERNS = [
  /at .+:\d+:\d+/,
  /File ".+", line \d+/,
  /\.java:\d+\)/,
  /\.go:\d+/,
  /SQL.*error|syntax.*near/i,
];

export function classifyResponse(
  statusCode: number,
  body: string,
  _headers: Record<string, string>
): string {
  if (statusCode === 401 || statusCode === 403) {
    return "pass";
  }

  if (statusCode >= 500) {
    return "crash";
  }

  if (statusCode >= 200 && statusCode < 300) {
    return "suspicious";
  }

  // 4xx: check for stack trace leakage
  for (const pattern of STACK_TRACE_PATTERNS) {
    if (pattern.test(body)) {
      return "error";
    }
  }

  return "pass";
}

export async function executePayloads(
  payloads: AttackPayload[],
  options: { concurrency: number; timeout: number },
  onResult: (result: ExecutionResult) => void
): Promise<ExecutionResult[]> {
  const queue = [...payloads];
  const results: ExecutionResult[] = [];

  async function worker(): Promise<void> {
    while (queue.length > 0) {
      const payload = queue.shift();
      if (payload === undefined) break;

      const start = Date.now();
      let statusCode = 0;
      let responseBody = "";
      let responseHeaders: Record<string, string> = {};

      try {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), options.timeout);

        const fetchOptions: RequestInit = {
          method: payload.method,
          headers: payload.headers,
          signal: controller.signal,
        };

        if (payload.body !== undefined && payload.method !== "GET") {
          fetchOptions.body =
            typeof payload.body === "string"
              ? payload.body
              : JSON.stringify(payload.body);
        }

        const response = await fetch(payload.url, fetchOptions);
        clearTimeout(timer);

        statusCode = response.status;
        responseBody = await response.text();

        response.headers.forEach((value, key) => {
          responseHeaders[key] = value;
        });
      } catch {
        statusCode = 0;
        responseBody = "fetch error";
        responseHeaders = {};
      }

      const responseTime = Date.now() - start;
      const classification =
        statusCode === 0
          ? "crash"
          : classifyResponse(statusCode, responseBody, responseHeaders);

      const result: ExecutionResult = {
        payload,
        statusCode,
        responseTime,
        responseBody,
        responseHeaders,
        classification: classification as ExecutionResult["classification"],
      };

      results.push(result);
      onResult(result);
    }
  }

  const workers = Array.from(
    { length: Math.min(options.concurrency, payloads.length || 1) },
    () => worker()
  );

  await Promise.all(workers);

  return results;
}
