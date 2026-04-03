import type { Endpoint } from "../types.js";

const HTTP_METHODS = ["get", "post", "put", "patch", "delete"] as const;

export function parseOpenAPIFromJSON(spec: Record<string, unknown>): Endpoint[] {
  const servers = spec.servers as Array<{ url?: string }> | undefined;
  const rawBaseUrl = servers?.[0]?.url ?? "";
  if (!rawBaseUrl) {
    throw new Error("OpenAPI spec has no servers[].url defined");
  }
  const baseUrl = rawBaseUrl.replace(/\/$/, "");
  const paths = (spec.paths ?? {}) as Record<string, Record<string, unknown>>;
  const endpoints: Endpoint[] = [];

  for (const [path, pathItem] of Object.entries(paths)) {
    for (const method of HTTP_METHODS) {
      const operation = pathItem[method] as Record<string, unknown> | undefined;
      if (!operation) continue;

      // Try application/json first, fall back to first available content type
      let bodySchema: unknown | undefined;
      const reqBody = operation.requestBody as Record<string, unknown> | undefined;
      const content = reqBody?.content as Record<string, { schema?: unknown }> | undefined;
      if (content) {
        bodySchema = content["application/json"]?.schema
          ?? Object.values(content)[0]?.schema;
      }

      const endpoint: Endpoint = {
        method: method.toUpperCase() as Endpoint["method"],
        url: `${baseUrl}${path}`,
        headers: {},
        auth: { type: "none" },
        ...(bodySchema !== undefined ? { bodySchema } : {}),
      };

      endpoints.push(endpoint);
    }
  }

  return endpoints;
}

export async function parseOpenAPIFromURL(url: string): Promise<Endpoint[]> {
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`Failed to fetch OpenAPI spec: ${response.status} ${response.statusText}`);
  }
  const spec = (await response.json()) as Record<string, unknown>;
  return parseOpenAPIFromJSON(spec);
}
