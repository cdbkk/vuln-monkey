import type { Endpoint } from "../types.js";
import { getParameterValue } from "./openapi-parameters.js";
import { isRecord, resolveLocalRef } from "./openapi-references.js";

type SecuritySelection = {
  auth: Endpoint["auth"];
  headers: Record<string, string>;
  credentialHeaderNames: string[];
  satisfied: boolean;
};

export function headersFromAuth(auth: Endpoint["auth"]): Record<string, string> {
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

export function authFromParameters(
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

function findHeader(
  headers: Record<string, string>,
  name: string
): [string, string] | undefined {
  return Object.entries(headers).find(([key]) => key.toLowerCase() === name.toLowerCase());
}

function findCookie(cookieHeader: string, name: string): string | undefined {
  for (const part of cookieHeader.split(";")) {
    const separator = part.indexOf("=");
    if (separator < 0) continue;
    const key = part.slice(0, separator).trim();
    if (key === name) return part.slice(separator + 1).trim();
  }
  return undefined;
}

export function mergeHeaders(...sources: Record<string, string>[]): Record<string, string> {
  const headers: Record<string, string> = {};
  for (const source of sources) {
    for (const [name, value] of Object.entries(source)) {
      if (name.toLowerCase() === "cookie" && headers.Cookie) {
        headers.Cookie = [...new Set(`${headers.Cookie}; ${value}`
          .split(";")
          .map((cookie) => cookie.trim())
          .filter(Boolean))].join("; ");
      } else {
        headers[name.toLowerCase() === "cookie" ? "Cookie" : name] = value;
      }
    }
  }
  return headers;
}

function securitySchemeSelection(
  scheme: Record<string, unknown>,
  availableHeaders: Record<string, string>
): SecuritySelection | undefined {
  const type = typeof scheme.type === "string" ? scheme.type.toLowerCase() : "";
  const httpScheme = typeof scheme.scheme === "string" ? scheme.scheme.toLowerCase() : "";

  if (type === "oauth2" || type === "openidconnect" || (type === "http" && httpScheme === "bearer")) {
    const header = findHeader(availableHeaders, "authorization");
    const value = header?.[1].match(/^Bearer\s+(.+)$/i)?.[1];
    return {
      auth: { type: "bearer", ...(value ? { value } : {}) },
      headers: value ? { Authorization: `Bearer ${value}` } : {},
      credentialHeaderNames: ["Authorization"],
      satisfied: value !== undefined,
    };
  }

  if (type === "basic" || (type === "http" && httpScheme === "basic")) {
    const header = findHeader(availableHeaders, "authorization");
    const value = header?.[1].match(/^Basic\s+(.+)$/i)?.[1];
    return {
      auth: { type: "basic", ...(value ? { value } : {}) },
      headers: value ? { Authorization: `Basic ${value}` } : {},
      credentialHeaderNames: ["Authorization"],
      satisfied: value !== undefined,
    };
  }

  if (type !== "apikey" || typeof scheme.name !== "string") return undefined;

  const location = typeof scheme.in === "string" ? scheme.in.toLowerCase() : "header";
  if (location === "header") {
    const header = findHeader(availableHeaders, scheme.name);
    return {
      auth: {
        type: "apikey",
        headerName: scheme.name,
        ...(header?.[1] ? { value: header[1] } : {}),
      },
      headers: header?.[1] ? { [scheme.name]: header[1] } : {},
      credentialHeaderNames: [scheme.name],
      satisfied: Boolean(header?.[1]),
    };
  }

  if (location === "cookie") {
    const cookieHeader = findHeader(availableHeaders, "cookie")?.[1];
    const value = cookieHeader ? findCookie(cookieHeader, scheme.name) : undefined;
    return {
      auth: {
        type: "apikey",
        headerName: "Cookie",
        ...(value ? { value } : {}),
      },
      headers: value ? { Cookie: `${scheme.name}=${value}` } : {},
      credentialHeaderNames: ["Cookie"],
      satisfied: value !== undefined,
    };
  }

  return {
    auth: { type: "apikey", headerName: scheme.name },
    headers: {},
    credentialHeaderNames: [],
    satisfied: false,
  };
}

export function authFromSecurity(
  spec: Record<string, unknown>,
  operation: Record<string, unknown>,
  availableHeaders: Record<string, string>
): SecuritySelection {
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
  if (!schemes || security.length === 0) {
    return { auth: { type: "none" }, headers: {}, credentialHeaderNames: [], satisfied: true };
  }

  let firstSupported: SecuritySelection | undefined;
  for (const requirement of security) {
    if (!isRecord(requirement)) continue;
    const schemeKeys = Object.keys(requirement);
    if (schemeKeys.length === 0) {
      return { auth: { type: "none" }, headers: {}, credentialHeaderNames: [], satisfied: true };
    }

    const selections = schemeKeys.map((schemeKey) => {
      const scheme = resolveLocalRef(spec, schemes[schemeKey]);
      return isRecord(scheme)
        ? securitySchemeSelection(scheme, availableHeaders)
        : undefined;
    });
    if (selections.some((selection) => selection === undefined)) continue;

    const supported = selections.filter((selection): selection is SecuritySelection =>
      selection !== undefined
    );
    const selection: SecuritySelection = {
      auth: supported[0]?.auth ?? { type: "none" },
      headers: mergeHeaders(...supported.map((item) => item.headers)),
      credentialHeaderNames: [...new Set(supported.flatMap((item) => item.credentialHeaderNames))],
      satisfied: supported.every((item) => item.satisfied),
    };
    firstSupported ??= selection;
    if (selection.satisfied) return selection;
  }

  return firstSupported ?? {
    auth: { type: "none" },
    headers: {},
    credentialHeaderNames: [],
    satisfied: false,
  };
}
