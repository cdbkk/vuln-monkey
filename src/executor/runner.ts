import type { AttackPayload, Endpoint, ExecutionResult, ResultClassification } from "../types.js";
import { requestPublicUrl } from "./public-http.js";

const STACK_TRACE_PATTERNS = [
  /at \S+:\d+:\d+/,
  /File ".+", line \d+/,
  /\.java:\d+\)/,
  /\.go:\d+/,
  /SQL[^]*?error|syntax[^]*?near/i,
];

const MAX_CONCURRENCY = 100;
const REDACTED = "[REDACTED]";
const SENSITIVE_REQUEST_HEADERS = new Set([
  "authorization",
  "proxy-authorization",
  "cookie",
  "x-auth-token",
  "api-key",
  "apikey",
  "x-api-key",
]);
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

function withoutAuthHeaders(
  headers: Record<string, string>,
  customAuthHeaders: string[] = []
): Record<string, string> {
  const customHeaders = new Set(customAuthHeaders.map((header) => header.toLowerCase()));
  return Object.fromEntries(
    Object.entries(headers).filter(([key]) =>
      !SENSITIVE_REQUEST_HEADERS.has(key.toLowerCase())
      && !customHeaders.has(key.toLowerCase())
    )
  );
}

function credentialHeaders(endpoint: Endpoint): string[] {
  return [...new Set([
    ...(endpoint.credentialHeaderNames ?? []),
    ...(endpoint.auth.headerName ? [endpoint.auth.headerName] : []),
  ])];
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
    ? payload.omitAuth
      ? withoutAuthHeaders(endpoint.headers, credentialHeaders(endpoint))
      : mergeHeaders(endpoint.headers, authHeaders(endpoint.auth))
    : {};
  const mergedHeaders = mergeHeaders(baseHeaders, payload.headers);
  const headers = payload.omitAuth && endpoint
    ? withoutAuthHeaders(mergedHeaders, credentialHeaders(endpoint))
    : mergedHeaders;
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

function redactPayload(payload: AttackPayload, customAuthHeaders: string[] = []): AttackPayload {
  const sensitiveHeaders = new Set(SENSITIVE_REQUEST_HEADERS);
  for (const header of customAuthHeaders) sensitiveHeaders.add(header.toLowerCase());
  return {
    ...payload,
    headers: redactHeaders(payload.headers, sensitiveHeaders),
  };
}

export function classifyResponse(
  statusCode: number,
  body: string,
  expectRejection = false,
): ResultClassification {
  if (expectRejection && statusCode >= 200 && statusCode < 300) {
    return "suspicious";
  }
  if (statusCode === 401 || statusCode === 403) {
    return hasInfoDisclosure(body) ? "error" : "pass";
  }

  if (statusCode >= 500) {
    return "crash";
  }

  if (statusCode >= 300 && statusCode < 400) {
    return "pass"; // Redirects handled explicitly
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
  allowPrivate?: boolean;
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
      const start = Date.now();
      let statusCode = 0;
      let responseBody = "";
      let responseHeaders: Record<string, string> = {};
      let tooLarge = false;

      try {
        const response = await requestPublicUrl(preparedPayload.url, {
          method: preparedPayload.method,
          headers: preparedPayload.headers,
          body: preparedPayload.body,
          timeout: options.timeout,
          origin: options.endpoint?.url,
          allowPrivate: options.allowPrivate,
        });
        statusCode = response.statusCode;
        responseBody = response.body;
        responseHeaders = response.headers;
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
          ? "unverified"
          : statusCode === 0
          ? "unverified"
          : classifyResponse(statusCode, responseBody, preparedPayload.expectRejection);

      const result: ExecutionResult = {
        payload: redactPayload(
          preparedPayload,
          options.endpoint ? credentialHeaders(options.endpoint) : []
        ),
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
