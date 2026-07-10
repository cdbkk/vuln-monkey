import { isRecord } from "./openapi-references.js";

function substituteServerVariables(server: Record<string, unknown>): string {
  const variables = isRecord(server.variables) ? server.variables : {};
  return (server.url as string).replace(/\{([^}]+)\}/g, (_match, name: string) => {
    const variable = variables[name];
    if (!isRecord(variable) || typeof variable.default !== "string") {
      throw new Error(`OpenAPI server variable "${name}" has no string default`);
    }
    return variable.default;
  });
}

function resolveServerUrl(rawBaseUrl: string, sourceUrl?: string): string {
  if (sourceUrl) {
    return new URL(rawBaseUrl, sourceUrl).toString().replace(/\/$/, "");
  }
  return rawBaseUrl.replace(/\/$/, "");
}

function getSwaggerBaseUrl(
  spec: Record<string, unknown>,
  sourceUrl?: string
): string | undefined {
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

function getServer(source: Record<string, unknown>): Record<string, unknown> | undefined {
  const servers = Array.isArray(source.servers) ? source.servers : undefined;
  return servers?.find((value): value is Record<string, unknown> =>
    isRecord(value) && typeof value.url === "string" && value.url.length > 0
  );
}

export function getBaseUrl(
  spec: Record<string, unknown>,
  pathItem?: Record<string, unknown>,
  operation?: Record<string, unknown>,
  sourceUrl?: string
): string {
  const server = (operation ? getServer(operation) : undefined)
    ?? (pathItem ? getServer(pathItem) : undefined)
    ?? getServer(spec);
  if (server) return resolveServerUrl(substituteServerVariables(server), sourceUrl);

  const swaggerBaseUrl = getSwaggerBaseUrl(spec, sourceUrl);
  if (swaggerBaseUrl) return swaggerBaseUrl;

  throw new Error("OpenAPI spec has no servers[].url defined");
}
