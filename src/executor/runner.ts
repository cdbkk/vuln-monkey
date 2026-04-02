import type { AttackPayload, ExecutionResult, ResultClassification } from "../types.js";

const STACK_TRACE_PATTERNS = [
  /at .+:\d+:\d+/,
  /File ".+", line \d+/,
  /\.java:\d+\)/,
  /\.go:\d+/,
  /SQL.*error|syntax.*near/i,
];

const BLOCKED_HOST_PATTERNS = [
  /^localhost$/i,
  /^127\.\d+\.\d+\.\d+$/,
  /^10\.\d+\.\d+\.\d+$/,
  /^172\.(1[6-9]|2\d|3[01])\.\d+\.\d+$/,
  /^192\.168\.\d+\.\d+$/,
  /^169\.254\.\d+\.\d+$/,
  /^\[?::1\]?$/,
  /^0\.0\.0\.0$/,
  /^metadata\.google\.internal$/i,
];

const MAX_RESPONSE_BYTES = 1024 * 1024; // 1 MB

function isUrlAllowed(urlStr: string): boolean {
  try {
    const parsed = new URL(urlStr);
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return false;
    const hostname = parsed.hostname;
    return !BLOCKED_HOST_PATTERNS.some((p) => p.test(hostname));
  } catch {
    return false;
  }
}

export function classifyResponse(
  statusCode: number,
  body: string,
  _headers: Record<string, string>
): ResultClassification {
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

      // SSRF protection: block internal/private URLs
      if (!isUrlAllowed(payload.url)) {
        const result: ExecutionResult = {
          payload,
          statusCode: 0,
          responseTime: 0,
          responseBody: `Blocked: URL not allowed (${payload.url})`,
          responseHeaders: {},
          classification: "pass",
        };
        results.push(result);
        onResult(result);
        continue;
      }

      const start = Date.now();
      let statusCode = 0;
      let responseBody = "";
      let responseHeaders: Record<string, string> = {};

      try {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), options.timeout);

        const fetchOptions: RequestInit = {
          method: payload.method,
          headers: payload.headers as Record<string, string>,
          signal: controller.signal,
          redirect: "manual",
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

        // Bounded response reading
        const contentLength = response.headers.get("content-length");
        if (contentLength && parseInt(contentLength, 10) > MAX_RESPONSE_BYTES) {
          responseBody = `[Response too large: ${contentLength} bytes]`;
        } else {
          const reader = response.body?.getReader();
          if (reader) {
            const chunks: Uint8Array[] = [];
            let totalSize = 0;
            let done = false;
            while (!done) {
              const { value, done: readerDone } = await reader.read();
              done = readerDone;
              if (value) {
                totalSize += value.length;
                if (totalSize > MAX_RESPONSE_BYTES) {
                  responseBody = `[Response truncated at ${MAX_RESPONSE_BYTES} bytes]`;
                  reader.cancel();
                  break;
                }
                chunks.push(value);
              }
            }
            if (!responseBody) {
              responseBody = new TextDecoder().decode(
                Buffer.concat(chunks)
              );
            }
          }
        }

        response.headers.forEach((value, key) => {
          responseHeaders[key] = value;
        });
      } catch (err) {
        statusCode = 0;
        responseBody = err instanceof Error ? err.message : "fetch error";
        responseHeaders = {};
      }

      const responseTime = Date.now() - start;
      const classification: ResultClassification =
        statusCode === 0
          ? "crash"
          : classifyResponse(statusCode, responseBody, responseHeaders);

      const result: ExecutionResult = {
        payload,
        statusCode,
        responseTime,
        responseBody,
        responseHeaders,
        classification,
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
