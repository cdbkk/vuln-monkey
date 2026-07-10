import type { Endpoint } from "../types.js";
import { isRecord, resolveLocalRef } from "./openapi-references.js";

export function getParameterValue(
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

export function getParameters(
  spec: Record<string, unknown>,
  pathItem: Record<string, unknown>,
  operation: Record<string, unknown>
): Record<string, unknown>[] {
  const parameters = new Map<string, Record<string, unknown>>();
  for (const source of [pathItem.parameters, operation.parameters]) {
    if (!Array.isArray(source)) continue;
    for (const value of source) {
      const parameter = resolveLocalRef(spec, value);
      if (!isRecord(parameter)) continue;
      const key = typeof parameter.in === "string" && typeof parameter.name === "string"
        ? `${parameter.in}:${parameter.name}`
        : `anonymous:${parameters.size}`;
      parameters.set(key, parameter);
    }
  }
  return [...parameters.values()];
}

export function applyPathParameters(
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

export function applyQueryParameters(
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

export function headersFromParameters(
  spec: Record<string, unknown>,
  parameters: Record<string, unknown>[]
): Record<string, string> {
  const headers: Record<string, string> = {};
  const cookies: string[] = [];

  for (const parameter of parameters) {
    if (typeof parameter.name !== "string") continue;
    const required = parameter.required === true;
    const name = parameter.name.toLowerCase();
    const isCredential = parameter.in === "cookie"
      || name === "authorization"
      || name === "x-api-key"
      || name === "api-key"
      || name === "apikey";
    const value = getParameterValue(
      spec,
      parameter,
      required && !isCredential ? "1" : undefined
    );
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
