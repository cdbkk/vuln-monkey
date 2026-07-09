import type { AttackPayload, Endpoint, ExecutionResult, ResultClassification } from "../types.js";
import { resolve as dnsResolve } from "node:dns/promises";
import { BlockList, isIP } from "node:net";
import { request as httpRequest, type IncomingHttpHeaders, type IncomingMessage, type RequestOptions } from "node:http";
import { request as httpsRequest } from "node:https";

const STACK_TRACE_PATTERNS = [
  /at \S+:\d+:\d+/,
  /File ".+", line \d+/,
  /\.java:\d+\)/,
  /\.go:\d+/,
  /SQL[^]*?error|syntax[^]*?near/i,
];

const MAX_RESPONSE_BYTES = 1024 * 1024; // 1 MB
const MAX_CONCURRENCY = 100;
const REDACTED = "[REDACTED]";
const SENSITIVE_REQUEST_HEADERS = new Set([
  "authorization",
  "cookie",
  "x-auth-token",
  "api-key",
  "apikey",
  "x-api-key",
]);
const SENSITIVE_RESPONSE_HEADERS = new Set(["set-cookie"]);

const PRIVATE_RANGES = [
  { address: "127.0.0.0", prefix: 8, type: "ipv4" as const },
  { address: "10.0.0.0", prefix: 8, type: "ipv4" as const },
  { address: "172.16.0.0", prefix: 12, type: "ipv4" as const },
  { address: "192.168.0.0", prefix: 16, type: "ipv4" as const },
  { address: "169.254.0.0", prefix: 16, type: "ipv4" as const },
  { address: "0.0.0.0", prefix: 8, type: "ipv4" as const },
  { address: "::", prefix: 128, type: "ipv6" as const },
  { address: "::1", prefix: 128, type: "ipv6" as const },
  { address: "fc00::", prefix: 7, type: "ipv6" as const },
  { address: "fe80::", prefix: 10, type: "ipv6" as const },
];

const PRIVATE_BLOCKS = new BlockList();
for (const range of PRIVATE_RANGES) {
  PRIVATE_BLOCKS.addSubnet(range.address, range.prefix, range.type);
}

function isPrivateIP(ip: string): boolean {
  const resolved = stripIpv6Brackets(ip);
  const version = isIP(resolved);
  if (!version) return false;
  return PRIVATE_BLOCKS.check(resolved, version === 4 ? "ipv4" : "ipv6");
}

function stripIpv6Brackets(hostname: string): string {
  return hostname.replace(/^\[(.*)]$/, "$1");
}

function rawHostname(urlStr: string): string {
  const match = urlStr.match(/^[a-z][a-z0-9+.-]*:\/\/(?:[^/?#@]*@)?(\[[^\]]+]|[^:/?#]+)/i);
  return match ? stripIpv6Brackets(match[1]) : "";
}

function isStandardIPv4Literal(hostname: string): boolean {
  const parts = hostname.split(".");
  return parts.length === 4 && parts.every((part) => {
    if (!/^(0|[1-9]\d{0,2})$/.test(part)) return false;
    return Number(part) <= 255;
  });
}

function isNumericIPv4Literal(hostname: string): boolean {
  return /^(?:0x[0-9a-f]+|\d+)(?:\.(?:0x[0-9a-f]+|\d+))*$/i.test(hostname)
    && !isStandardIPv4Literal(hostname);
}

function hasHeader(headers: Record<string, string>, name: string): boolean {
  const lowerName = name.toLowerCase();
  return Object.keys(headers).some((key) => key.toLowerCase() === lowerName);
}

function setHeader(headers: Record<string, string>, name: string, value: string): void {
  const lowerName = name.toLowerCase();
  for (const key of Object.keys(headers)) {
    if (key.toLowerCase() === lowerName) delete headers[key];
  }
  headers[name] = value;
}

function mergeHeaders(
  base: Record<string, string>,
  override: Record<string, string>
): Record<string, string> {
  const headers = { ...base };
  for (const [key, value] of Object.entries(override)) {
    setHeader(headers, key, value);
  }
  return headers;
}

function authHeaders(auth: Endpoint["auth"]): Record<string, string> {
  if (auth.type === "bearer" && auth.value) {
    return { Authorization: `Bearer ${auth.value}` };
  }
  if (auth.type === "basic" && auth.value) {
    return { Authorization: `Basic ${auth.value}` };
  }
  if (auth.type === "apikey" && auth.headerName && auth.value) {
    return { [auth.headerName]: auth.value };
  }
  return {};
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function mergeBody(base: unknown, override: unknown): unknown {
  if (override === undefined) return base;
  if (isRecord(base) && isRecord(override)) return { ...base, ...override };
  return override;
}

function preparePayload(payload: AttackPayload, endpoint?: Endpoint): AttackPayload {
  const baseHeaders = endpoint
    ? mergeHeaders(endpoint.headers, authHeaders(endpoint.auth))
    : {};
  const headers = mergeHeaders(baseHeaders, payload.headers);
  const body = endpoint ? mergeBody(endpoint.body, payload.body) : payload.body;

  if (
    body != null
    && payload.method !== "GET"
    && typeof body === "object"
    && !hasHeader(headers, "Content-Type")
  ) {
    headers["Content-Type"] = "application/json";
  }

  return { ...payload, headers, body };
}

type AllowedUrl = {
  url: URL;
  address: string;
  family: 4 | 6;
};

async function resolveHostname(hostname: string): Promise<string[]> {
  const results = await Promise.allSettled([
    dnsResolve(hostname, "A"),
    dnsResolve(hostname, "AAAA"),
  ]);

  return results.flatMap((result) => result.status === "fulfilled" ? result.value : []);
}

async function isUrlAllowed(urlStr: string): Promise<AllowedUrl | null> {
  try {
    const parsed = new URL(urlStr);
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return null;

    const rawHost = rawHostname(urlStr);
    if (rawHost && isNumericIPv4Literal(rawHost)) return null;

    const hostname = stripIpv6Brackets(parsed.hostname);

    // Block known dangerous hostnames
    if (/^localhost$/i.test(hostname)) return null;
    if (/^metadata\.google\.internal$/i.test(hostname)) return null;

    // If hostname is an IP address (any notation), validate it
    const family = isIP(hostname);
    if (family) {
      return isPrivateIP(hostname) ? null : { url: parsed, address: hostname, family: family as 4 | 6 };
    }

    // Numeric hostnames that aren't caught by isIP (decimal, hex, octal)
    if (/^\d+$/.test(hostname) || /^0x[0-9a-f]+$/i.test(hostname) || /^0\d+/.test(hostname)) {
      return null; // Block all numeric/hex/octal IP notations
    }

    const addresses = await resolveHostname(hostname);
    if (addresses.length === 0 || addresses.some(isPrivateIP)) return null;

    const address = addresses[0];
    const resolvedFamily = isIP(address);
    return resolvedFamily ? { url: parsed, address, family: resolvedFamily as 4 | 6 } : null;
  } catch {
    return null;
  }
}

function redactHeaders(
  headers: Record<string, string>,
  sensitiveHeaders: Set<string>
): Record<string, string> {
  return Object.fromEntries(
    Object.entries(headers).map(([key, value]) => [
      key,
      sensitiveHeaders.has(key.toLowerCase()) ? REDACTED : value,
    ])
  );
}

function redactPayload(payload: AttackPayload): AttackPayload {
  return {
    ...payload,
    headers: redactHeaders(payload.headers, SENSITIVE_REQUEST_HEADERS),
  };
}

function responseHeadersToRecord(headers: IncomingHttpHeaders): Record<string, string> {
  return Object.fromEntries(
    Object.entries(headers).map(([key, value]) => [
      key,
      SENSITIVE_RESPONSE_HEADERS.has(key.toLowerCase())
        ? REDACTED
        : Array.isArray(value) ? value.join(", ") : String(value ?? ""),
    ])
  );
}

type PinnedResponse = {
  statusCode: number;
  responseBody: string;
  responseHeaders: Record<string, string>;
  tooLarge: boolean;
};

function requestPinned(
  target: AllowedUrl,
  payload: AttackPayload,
  timeout: number
): Promise<PinnedResponse> {
  return new Promise((resolve, reject) => {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeout);
    let settled = false;

    const finish = (err: Error | null, result?: PinnedResponse): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (err) reject(err);
      else resolve(result!);
    };

    const headers = payload.headers as Record<string, string>;
    const requestOptions: RequestOptions = {
      method: payload.method,
      headers,
      signal: controller.signal,
      lookup: (_hostname, _options, callback) => callback(null, target.address, target.family),
    };

    const handleResponse = (response: IncomingMessage): void => {
      const statusCode = response.statusCode ?? 0;
      const responseHeaders = responseHeadersToRecord(response.headers);
      const contentLength = response.headers["content-length"];
      const length = Array.isArray(contentLength) ? contentLength[0] : contentLength;

      if (length && parseInt(length, 10) > MAX_RESPONSE_BYTES) {
        finish(null, {
          statusCode,
          responseHeaders,
          responseBody: `[Response too large: ${length} bytes]`,
          tooLarge: true,
        });
        response.destroy();
        return;
      }

      const chunks: Buffer[] = [];
      let totalSize = 0;

      response.on("data", (chunk: Buffer | string) => {
        const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
        totalSize += buffer.length;
        if (totalSize > MAX_RESPONSE_BYTES) {
          finish(null, {
            statusCode,
            responseHeaders,
            responseBody: `[Response truncated at ${MAX_RESPONSE_BYTES} bytes]`,
            tooLarge: true,
          });
          response.destroy();
          return;
        }
        chunks.push(buffer);
      });

      response.on("end", () => {
        finish(null, {
          statusCode,
          responseHeaders,
          responseBody: Buffer.concat(chunks).toString(),
          tooLarge: false,
        });
      });

      response.on("error", finish);
    };

    const request = target.url.protocol === "https:"
      ? httpsRequest(target.url, requestOptions, handleResponse)
      : httpRequest(target.url, requestOptions, handleResponse);

    request.on("error", finish);

    if (payload.body != null && payload.method !== "GET") {
      request.write(
        typeof payload.body === "string"
          ? payload.body
          : JSON.stringify(payload.body)
      );
    }

    request.end();
  });
}

export function classifyResponse(
  statusCode: number,
  body: string,
): ResultClassification {
  if (statusCode === 401 || statusCode === 403) {
    return hasInfoDisclosure(body) ? "error" : "pass";
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

  if (hasInfoDisclosure(body)) return "error";

  return "pass";
}

function hasInfoDisclosure(body: string): boolean {
  return STACK_TRACE_PATTERNS.some((pattern) => pattern.test(body));
}

type ExecuteOptions = {
  concurrency: number;
  timeout: number;
  endpoint?: Endpoint;
};

export async function executePayloads(
  payloads: AttackPayload[],
  options: ExecuteOptions,
  onResult: (result: ExecutionResult) => void
): Promise<ExecutionResult[]> {
  const queue = [...payloads];
  const results: ExecutionResult[] = [];

  async function worker(): Promise<void> {
    while (queue.length > 0) {
      const payload = queue.shift();
      if (payload === undefined) break;

      const preparedPayload = preparePayload(payload, options.endpoint);

      // SSRF protection: block internal/private URLs
      const allowedUrl = await isUrlAllowed(preparedPayload.url);
      if (!allowedUrl) {
        const result: ExecutionResult = {
          payload: redactPayload(preparedPayload),
          statusCode: 0,
          responseTime: 0,
          responseBody: `Blocked: URL not allowed (${preparedPayload.url})`,
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
      let tooLarge = false;

      try {
        const response = await requestPinned(allowedUrl, preparedPayload, options.timeout);
        statusCode = response.statusCode;
        responseBody = response.responseBody;
        responseHeaders = response.responseHeaders;
        tooLarge = response.tooLarge;
      } catch (err) {
        statusCode = 0;
        responseBody = err instanceof Error ? err.message : "fetch error";
        responseHeaders = {};
      }

      const responseTime = Date.now() - start;

      // Network errors are not server crashes
      const classification: ResultClassification =
        tooLarge
          ? "suspicious"
          : statusCode === 0
          ? "error"
          : classifyResponse(statusCode, responseBody);

      const result: ExecutionResult = {
        payload: redactPayload(preparedPayload),
        statusCode,
        responseTime,
        responseBody,
        responseHeaders,
        classification,
        ...(tooLarge ? { finding: "Response too large to classify" } : {}),
      };

      results.push(result);
      onResult(result);
    }
  }

  const workerCount = Math.min(
    Math.max(1, options.concurrency),
    MAX_CONCURRENCY,
    payloads.length || 1
  );
  const workers = Array.from(
    { length: workerCount },
    () => worker()
  );

  await Promise.all(workers);

  return results;
}
