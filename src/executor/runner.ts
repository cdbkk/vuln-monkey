import type { AttackPayload, ExecutionResult, ResultClassification } from "../types.js";
import { resolve as dnsResolve } from "node:dns/promises";
import { isIP } from "node:net";

const STACK_TRACE_PATTERNS = [
  /at \S+:\d+:\d+/,
  /File ".+", line \d+/,
  /\.java:\d+\)/,
  /\.go:\d+/,
  /SQL[^]*?error|syntax[^]*?near/i,
];

const MAX_RESPONSE_BYTES = 1024 * 1024; // 1 MB

const PRIVATE_RANGES = [
  { start: 0x7F000000, end: 0x7FFFFFFF }, // 127.0.0.0/8
  { start: 0x0A000000, end: 0x0AFFFFFF }, // 10.0.0.0/8
  { start: 0xAC100000, end: 0xAC1FFFFF }, // 172.16.0.0/12
  { start: 0xC0A80000, end: 0xC0A8FFFF }, // 192.168.0.0/16
  { start: 0xA9FE0000, end: 0xA9FEFFFF }, // 169.254.0.0/16
  { start: 0x00000000, end: 0x00000000 }, // 0.0.0.0
];

function ipToInt(ip: string): number | null {
  const parts = ip.split(".");
  if (parts.length !== 4) return null;
  let result = 0;
  for (const part of parts) {
    const n = parseInt(part, 10);
    if (isNaN(n) || n < 0 || n > 255) return null;
    result = (result << 8) | n;
  }
  return result >>> 0;
}

function isPrivateIP(ip: string): boolean {
  // Handle IPv6-mapped IPv4 (::ffff:127.0.0.1)
  const mapped = ip.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/i);
  const resolved = mapped ? mapped[1] : ip;

  // Handle pure IPv6 loopback
  if (resolved === "::1" || resolved === "[::1]") return true;

  const num = ipToInt(resolved);
  if (num === null) return false;

  return PRIVATE_RANGES.some((r) => num >= r.start && num <= r.end);
}

function isUrlAllowed(urlStr: string): boolean {
  try {
    const parsed = new URL(urlStr);
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return false;

    const hostname = parsed.hostname.replace(/^\[|]$/g, "");

    // Block known dangerous hostnames
    if (/^localhost$/i.test(hostname)) return false;
    if (/^metadata\.google\.internal$/i.test(hostname)) return false;

    // If hostname is an IP address (any notation), validate it
    if (isIP(hostname)) {
      return !isPrivateIP(hostname);
    }

    // Numeric hostnames that aren't caught by isIP (decimal, hex, octal)
    if (/^\d+$/.test(hostname) || /^0x[0-9a-f]+$/i.test(hostname) || /^0\d+/.test(hostname)) {
      return false; // Block all numeric/hex/octal IP notations
    }

    return true;
  } catch {
    return false;
  }
}

export function classifyResponse(
  statusCode: number,
  body: string,
): ResultClassification {
  if (statusCode === 401 || statusCode === 403) {
    return "pass";
  }

  if (statusCode >= 500) {
    return "crash";
  }

  if (statusCode >= 300 && statusCode < 400) {
    return "pass"; // Redirects handled explicitly
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
      let timer: ReturnType<typeof setTimeout> | undefined;

      try {
        const controller = new AbortController();
        timer = setTimeout(() => controller.abort(), options.timeout);

        const fetchOptions: RequestInit = {
          method: payload.method,
          headers: payload.headers as Record<string, string>,
          signal: controller.signal,
          redirect: "manual",
        };

        if (payload.body != null && payload.method !== "GET") {
          fetchOptions.body =
            typeof payload.body === "string"
              ? payload.body
              : JSON.stringify(payload.body);
        }

        const response = await fetch(payload.url, fetchOptions);
        clearTimeout(timer);
        timer = undefined;

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
        if (timer) clearTimeout(timer);
        statusCode = 0;
        responseBody = err instanceof Error ? err.message : "fetch error";
        responseHeaders = {};
      }

      const responseTime = Date.now() - start;

      // Network errors are not server crashes
      const classification: ResultClassification =
        statusCode === 0
          ? "error"
          : classifyResponse(statusCode, responseBody);

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
