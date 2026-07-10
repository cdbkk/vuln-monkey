import { request as httpRequest, type IncomingHttpHeaders, type IncomingMessage, type RequestOptions } from "node:http";
import { request as httpsRequest } from "node:https";
import { remaining, resolvePublicTarget, type PublicTarget } from "./public-target.js";

const DEFAULT_TIMEOUT = 10_000;
const MAX_RESPONSE_BYTES = 1024 * 1024;
const MAX_SPEC_BYTES = 10 * 1024 * 1024;
const MAX_REDIRECTS = 3;
const REDACTED = "[REDACTED]";
const SENSITIVE_RESPONSE_HEADERS = new Set(["set-cookie"]);

export type PublicHttpResponse = {
  statusCode: number;
  body: string;
  headers: Record<string, string>;
  tooLarge: boolean;
};

type PublicHttpOptions = {
  method: string;
  headers: Record<string, string>;
  body?: unknown;
  timeout: number;
  origin?: string;
  maxResponseBytes?: number;
  allowPrivate?: boolean;
};

function requestBody(options: PublicHttpOptions): string | Uint8Array | undefined {
  if (options.body === undefined || options.method === "GET" || options.method === "HEAD") {
    return undefined;
  }
  if (typeof options.body === "string" || options.body instanceof Uint8Array) {
    return options.body;
  }

  const contentType = Object.entries(options.headers)
    .find(([key]) => key.toLowerCase() === "content-type")?.[1]
    .toLowerCase() ?? "application/json";

  if (contentType.includes("application/x-www-form-urlencoded")) {
    if (typeof options.body !== "object" || options.body === null || Array.isArray(options.body)) {
      throw new Error("URL-encoded request bodies must be objects");
    }
    const form = new URLSearchParams();
    for (const [key, value] of Object.entries(options.body)) {
      if (Array.isArray(value)) {
        for (const item of value) form.append(key, String(item));
      } else {
        form.append(key, String(value ?? ""));
      }
    }
    return form.toString();
  }

  if (contentType.includes("json")) return JSON.stringify(options.body);
  throw new Error(`Unsupported structured request body for ${contentType}`);
}

function responseHeaders(headers: IncomingHttpHeaders): Record<string, string> {
  return Object.fromEntries(Object.entries(headers).map(([key, value]) => [
    key,
    SENSITIVE_RESPONSE_HEADERS.has(key.toLowerCase())
      ? REDACTED
      : Array.isArray(value) ? value.join(", ") : String(value ?? ""),
  ]));
}

function requestAddress(
  target: PublicTarget,
  address: { address: string; family: 4 | 6 },
  options: PublicHttpOptions,
  deadline: number
): Promise<PublicHttpResponse> {
  return new Promise((resolve, reject) => {
    const controller = new AbortController();
    const wait = remaining(deadline);
    if (wait === 0) {
      reject(new Error("Request timed out"));
      return;
    }

    const timer = setTimeout(() => controller.abort(), wait);
    const maxResponseBytes = options.maxResponseBytes ?? MAX_RESPONSE_BYTES;
    let settled = false;
    const finish = (error: Error | null, response?: PublicHttpResponse): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (error) reject(error);
      else resolve(response!);
    };

    const requestOptions: RequestOptions = {
      method: options.method,
      headers: options.headers,
      signal: controller.signal,
      lookup: (_hostname, _lookupOptions, callback) =>
        callback(null, address.address, address.family),
    };
    const onResponse = (incoming: IncomingMessage): void => {
      const statusCode = incoming.statusCode ?? 0;
      const headers = responseHeaders(incoming.headers);
      const rawLength = incoming.headers["content-length"];
      const contentLength = Array.isArray(rawLength) ? rawLength[0] : rawLength;

      if (contentLength && parseInt(contentLength, 10) > maxResponseBytes) {
        finish(null, {
          statusCode,
          headers,
          body: `[Response too large: ${contentLength} bytes]`,
          tooLarge: true,
        });
        incoming.destroy();
        return;
      }

      const chunks: Buffer[] = [];
      let size = 0;
      incoming.on("data", (chunk: Buffer | string) => {
        const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
        size += buffer.length;
        if (size > maxResponseBytes) {
          finish(null, {
            statusCode,
            headers,
            body: `[Response truncated at ${maxResponseBytes} bytes]`,
            tooLarge: true,
          });
          incoming.destroy();
          return;
        }
        chunks.push(buffer);
      });
      incoming.on("end", () => finish(null, {
        statusCode,
        headers,
        body: Buffer.concat(chunks).toString(),
        tooLarge: false,
      }));
      incoming.on("error", finish);
    };

    const request = target.url.protocol === "https:"
      ? httpsRequest(target.url, requestOptions, onResponse)
      : httpRequest(target.url, requestOptions, onResponse);
    request.on("error", finish);
    const body = requestBody(options);
    if (body !== undefined) request.write(body);
    request.end();
  });
}

export async function requestPublicUrl(
  url: string,
  options: PublicHttpOptions
): Promise<PublicHttpResponse> {
  const deadline = Date.now() + options.timeout;
  const target = await resolvePublicTarget(url, deadline, options.origin, options.allowPrivate);
  let lastError: Error | undefined;

  for (const address of target.addresses) {
    try {
      return await requestAddress(target, address, options, deadline);
    } catch (error) {
      lastError = error instanceof Error ? error : new Error("Request failed");
    }
  }

  throw lastError ?? new Error("Request failed");
}

export async function readPublicUrl(
  url: string,
  timeout = DEFAULT_TIMEOUT,
  allowPrivate = false
): Promise<string> {
  const deadline = Date.now() + timeout;
  let currentUrl = url;

  for (let redirects = 0; redirects <= MAX_REDIRECTS; redirects++) {
    const response = await requestPublicUrl(currentUrl, {
      method: "GET",
      headers: {},
      timeout: remaining(deadline),
      maxResponseBytes: MAX_SPEC_BYTES,
      allowPrivate,
    });
    if (response.tooLarge) throw new Error(response.body);
    if (response.statusCode >= 300 && response.statusCode < 400) {
      const location = response.headers.location;
      if (!location) throw new Error(`Redirect response missing Location header`);
      currentUrl = new URL(location, currentUrl).toString();
      continue;
    }
    if (response.statusCode < 200 || response.statusCode >= 300) {
      throw new Error(`Request failed with HTTP ${response.statusCode}`);
    }
    return response.body;
  }

  throw new Error(`Too many redirects`);
}
