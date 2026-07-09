import type { Endpoint } from "../types.js";

const HTTP_METHODS = ["get", "post", "put", "patch", "delete"] as const;
const OPENAPI_FETCH_TIMEOUT_MS = 30_000;
const MAX_OPENAPI_BYTES = 10 * 1024 * 1024;
const DEFAULT_BEARER_TOKEN = "vuln-monkey-token";
const DEFAULT_BASIC_TOKEN = "dXNlcjpwYXNz";
const DEFAULT_API_KEY = "vuln-monkey-api-key";

type RequestBodyInfo = {
  body?: unknown;
  bodySchema?: unknown;
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function resolveLocalRef(spec: Record<string, unknown>, value: unknown): unknown {
  if (!isRecord(value)) return value;
  const ref = value.$ref;
  if (typeof ref !== "string" || !ref.startsWith("#/")) return value;

  let current: unknown = spec;
  for (const part of ref.slice(2).split("/")) {
    const key = part.replace(/~1/g, "/").replace(/~0/g, "~");
    if (!isRecord(current) || !(key in current)) return undefined;
    current = current[key];
  }
  return current;
}

function getParameterValue(
  spec: Record<string, unknown>,
  parameter: Record<string, unknown>,
  fallback?: string
): string | undefined {
  const schema = resolveLocalRef(spec, parameter.schema);
  const schemaRecord = isRecord(schema) ? schema : undefined;
  const value = parameter.example
    ?? parameter.default
    ?? schemaRecord?.example
    ?? schemaRecord?.default;
  return value == null ? fallback : String(value);
}

function getParameters(
  spec: Record<string, unknown>,
  pathItem: Record<string, unknown>,
  operation: Record<string, unknown>
): Record<string, unknown>[] {
  const parameters = [
    ...(Array.isArray(pathItem.parameters) ? pathItem.parameters : []),
    ...(Array.isArray(operation.parameters) ? operation.parameters : []),
  ];
  return parameters
    .map((parameter) => resolveLocalRef(spec, parameter))
    .filter(isRecord);
}

function applyPathParameters(
  path: string,
  spec: Record<string, unknown>,
  parameters: Record<string, unknown>[]
): string {
  const values = new Map<string, string>();
  for (const parameter of parameters) {
    if (parameter.in === "path" && typeof parameter.name === "string") {
      values.set(parameter.name, getParameterValue(spec, parameter, "1") ?? "1");
    }
  }
  return path.replace(/\{([^}]+)\}/g, (_match, name: string) =>
    encodeURIComponent(values.get(name) ?? "1")
  );
}

function applyQueryParameters(
  url: string,
  spec: Record<string, unknown>,
  parameters: Record<string, unknown>[]
): string {
  const query = new URLSearchParams();
  for (const parameter of parameters) {
    if (
      parameter.in !== "query"
      || parameter.required !== true
      || typeof parameter.name !== "string"
    ) {
      continue;
    }
    query.append(parameter.name, getParameterValue(spec, parameter, "1") ?? "1");
  }

  const queryString = query.toString();
  if (!queryString) return url;

  const separator = url.includes("?")
    ? (url.endsWith("?") || url.endsWith("&") ? "" : "&")
    : "?";
  return `${url}${separator}${queryString}`;
}

function headersFromParameters(
  spec: Record<string, unknown>,
  parameters: Record<string, unknown>[]
): Record<string, string> {
  const headers: Record<string, string> = {};
  const cookies: string[] = [];

  for (const parameter of parameters) {
    if (typeof parameter.name !== "string") continue;
    const required = parameter.required === true;
    const value = getParameterValue(spec, parameter, required ? "1" : undefined);
    if (value === undefined) continue;

    if (parameter.in === "header") {
      headers[parameter.name] = value;
    } else if (parameter.in === "cookie") {
      cookies.push(`${encodeURIComponent(parameter.name)}=${encodeURIComponent(value)}`);
    }
  }

  if (cookies.length > 0) {
    headers.Cookie = headers.Cookie
      ? `${headers.Cookie}; ${cookies.join("; ")}`
      : cookies.join("; ");
  }

  return headers;
}

function headersFromAuth(auth: Endpoint["auth"]): Record<string, string> {
  if (auth.type === "bearer") {
    return { Authorization: `Bearer ${auth.value ?? DEFAULT_BEARER_TOKEN}` };
  }
  if (auth.type === "basic") {
    return { Authorization: `Basic ${auth.value ?? DEFAULT_BASIC_TOKEN}` };
  }
  if (auth.type === "apikey" && auth.headerName) {
    return { [auth.headerName]: auth.value ?? DEFAULT_API_KEY };
  }
  return {};
}

function authFromParameters(
  spec: Record<string, unknown>,
  parameters: Record<string, unknown>[]
): Endpoint["auth"] {
  for (const parameter of parameters) {
    if (parameter.in !== "header" || typeof parameter.name !== "string") continue;
    const lowerName = parameter.name.toLowerCase();
    const value = getParameterValue(spec, parameter);
    const lowerValue = value?.toLowerCase() ?? "";

    if (lowerName === "authorization") {
      if (lowerValue.startsWith("basic ")) {
        return { type: "basic", value: value?.slice(6) };
      }
      if (lowerValue.startsWith("bearer ")) {
        return { type: "bearer", value: value?.slice(7) };
      }
      return value ? { type: "bearer", value } : { type: "bearer" };
    }

    if (lowerName === "x-api-key" || lowerName === "api-key" || lowerName === "apikey") {
      return { type: "apikey", headerName: parameter.name, ...(value ? { value } : {}) };
    }
  }
  return { type: "none" };
}

function authFromSecurity(
  spec: Record<string, unknown>,
  operation: Record<string, unknown>
): Endpoint["auth"] {
  const security = Array.isArray(operation.security)
    ? operation.security
    : Array.isArray(spec.security)
      ? spec.security
      : [];
  const components = isRecord(spec.components) ? spec.components : undefined;
  const schemes = isRecord(components?.securitySchemes)
    ? components.securitySchemes
    : isRecord(spec.securityDefinitions)
      ? spec.securityDefinitions
      : undefined;
  if (!schemes) return { type: "none" };

  for (const requirement of security) {
    if (!isRecord(requirement)) continue;
    for (const schemeKey of Object.keys(requirement)) {
      const scheme = resolveLocalRef(spec, schemes[schemeKey]);
      if (!isRecord(scheme)) continue;
      const type = typeof scheme.type === "string" ? scheme.type.toLowerCase() : "";

      if (type === "http") {
        const httpScheme = typeof scheme.scheme === "string" ? scheme.scheme.toLowerCase() : "";
        if (httpScheme === "basic") return { type: "basic", value: DEFAULT_BASIC_TOKEN };
        if (httpScheme === "bearer") return { type: "bearer", value: DEFAULT_BEARER_TOKEN };
      } else if (type === "apikey" && typeof scheme.name === "string") {
        const location = typeof scheme.in === "string" ? scheme.in.toLowerCase() : "header";
        if (location === "header") {
          return { type: "apikey", headerName: scheme.name, value: DEFAULT_API_KEY };
        }
      }
    }
  }
  return { type: "none" };
}

function getSchemaExample(schema: unknown): unknown | undefined {
  if (!isRecord(schema)) return undefined;
  if ("example" in schema) return schema.example;
  if ("default" in schema) return schema.default;
  return undefined;
}

function getExampleValue(spec: Record<string, unknown>, example: unknown): unknown | undefined {
  const resolved = resolveLocalRef(spec, example);
  if (isRecord(resolved) && "value" in resolved) return resolved.value;
  return undefined;
}

function getBodyExample(
  spec: Record<string, unknown>,
  mediaType: Record<string, unknown>,
  schema: unknown
): unknown | undefined {
  if ("example" in mediaType) return mediaType.example;

  const examples = isRecord(mediaType.examples) ? mediaType.examples : undefined;
  if (examples) {
    for (const example of Object.values(examples)) {
      const value = getExampleValue(spec, example);
      if (value !== undefined) return value;
    }
  }

  return getSchemaExample(schema);
}

function getRequestBody(
  spec: Record<string, unknown>,
  operation: Record<string, unknown>,
  parameters: Record<string, unknown>[]
): RequestBodyInfo {
  const reqBody = resolveLocalRef(spec, operation.requestBody);
  if (isRecord(reqBody)) {
    const content = isRecord(reqBody.content) ? reqBody.content : undefined;
    if (content) {
      const jsonContent = content["application/json"];
      const mediaType = isRecord(jsonContent)
        ? jsonContent
        : Object.values(content).find(isRecord);
      if (mediaType) {
        const bodySchema = resolveLocalRef(spec, mediaType.schema);
        const body = getBodyExample(spec, mediaType, bodySchema);
        return {
          ...(body !== undefined ? { body } : {}),
          ...(bodySchema !== undefined ? { bodySchema } : {}),
        };
      }
    }
  }

  const bodyParameter = parameters.find((parameter) => parameter.in === "body");
  if (!bodyParameter) return {};

  const bodySchema = resolveLocalRef(spec, bodyParameter.schema);
  const body = "example" in bodyParameter
    ? bodyParameter.example
    : getSchemaExample(bodySchema);
  return {
    ...(body !== undefined ? { body } : {}),
    ...(bodySchema !== undefined ? { bodySchema } : {}),
  };
}

function resolveServerUrl(rawBaseUrl: string, sourceUrl?: string): string {
  if (sourceUrl) {
    return new URL(rawBaseUrl, sourceUrl).toString().replace(/\/$/, "");
  }
  return rawBaseUrl.replace(/\/$/, "");
}

function getSwaggerBaseUrl(spec: Record<string, unknown>, sourceUrl?: string): string | undefined {
  const source = sourceUrl ? new URL(sourceUrl) : undefined;
  const host = typeof spec.host === "string" ? spec.host : source?.host;
  if (!host) return undefined;

  const schemes = Array.isArray(spec.schemes)
    ? spec.schemes.filter((scheme): scheme is string => typeof scheme === "string")
    : [];
  const scheme = schemes[0] ?? source?.protocol.replace(/:$/, "") ?? "https";
  const rawBasePath = typeof spec.basePath === "string" ? spec.basePath : "";
  const basePath = rawBasePath && !rawBasePath.startsWith("/")
    ? `/${rawBasePath}`
    : rawBasePath;
  return `${scheme}://${host}${basePath}`.replace(/\/$/, "");
}

function getBaseUrl(spec: Record<string, unknown>, sourceUrl?: string): string {
  const servers = Array.isArray(spec.servers) ? spec.servers : undefined;
  const server = servers?.find((value): value is { url: string } =>
    isRecord(value) && typeof value.url === "string" && value.url.length > 0
  );
  if (server) return resolveServerUrl(server.url, sourceUrl);

  const swaggerBaseUrl = getSwaggerBaseUrl(spec, sourceUrl);
  if (swaggerBaseUrl) return swaggerBaseUrl;

  throw new Error("OpenAPI spec has no servers[].url defined");
}

async function readOpenAPIBody(response: Response): Promise<string> {
  const contentLength = response.headers.get("content-length");
  const parsedLength = contentLength ? parseInt(contentLength, 10) : 0;
  if (!isNaN(parsedLength) && parsedLength > MAX_OPENAPI_BYTES) {
    throw new Error(`OpenAPI spec too large: ${contentLength} bytes`);
  }

  const reader = response.body?.getReader();
  if (!reader) return "";

  const chunks: Uint8Array[] = [];
  let totalSize = 0;
  let done = false;
  while (!done) {
    const { value, done: readerDone } = await reader.read();
    done = readerDone;
    if (value) {
      totalSize += value.length;
      if (totalSize > MAX_OPENAPI_BYTES) {
        await reader.cancel();
        throw new Error(`OpenAPI spec too large: over ${MAX_OPENAPI_BYTES} bytes`);
      }
      chunks.push(value);
    }
  }

  return new TextDecoder().decode(Buffer.concat(chunks));
}

export function parseOpenAPIFromJSON(
  spec: Record<string, unknown>,
  sourceUrl?: string
): Endpoint[] {
  const baseUrl = getBaseUrl(spec, sourceUrl);
  const paths = (spec.paths ?? {}) as Record<string, Record<string, unknown>>;
  const endpoints: Endpoint[] = [];

  for (const [path, pathItem] of Object.entries(paths)) {
    if (!isRecord(pathItem)) continue;
    for (const method of HTTP_METHODS) {
      const operation = pathItem[method];
      if (!isRecord(operation)) continue;

      const parameters = getParameters(spec, pathItem, operation);
      const requestBody = getRequestBody(spec, operation, parameters);
      const parameterAuth = authFromParameters(spec, parameters);
      const securityAuth = authFromSecurity(spec, operation);
      const auth = parameterAuth.type !== "none" ? parameterAuth : securityAuth;
      const url = applyQueryParameters(
        `${baseUrl}${applyPathParameters(path, spec, parameters)}`,
        spec,
        parameters
      );

      const endpoint: Endpoint = {
        method: method.toUpperCase() as Endpoint["method"],
        url,
        headers: {
          ...headersFromParameters(spec, parameters),
          ...headersFromAuth(auth),
        },
        auth,
        ...requestBody,
      };

      endpoints.push(endpoint);
    }
  }

  return endpoints;
}

export async function parseOpenAPIFromURL(url: string): Promise<Endpoint[]> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), OPENAPI_FETCH_TIMEOUT_MS);
  try {
    const response = await fetch(url, { signal: controller.signal, redirect: "manual" });
    if (response.status >= 300 && response.status < 400) {
      throw new Error(`OpenAPI spec redirects are not followed: ${response.status}`);
    }
    if (!response.ok) {
      throw new Error(`Failed to fetch OpenAPI spec: ${response.status} ${response.statusText}`);
    }
    const spec = JSON.parse(await readOpenAPIBody(response)) as Record<string, unknown>;
    return parseOpenAPIFromJSON(spec, url);
  } finally {
    clearTimeout(timer);
  }
}
