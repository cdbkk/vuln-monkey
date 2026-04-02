import type { Endpoint } from "../types.js";

const HTTP_METHODS = ["get", "post", "put", "patch", "delete"] as const;

export function parseOpenAPIFromJSON(spec: any): Endpoint[] {
  const rawBaseUrl: string = spec.servers?.[0]?.url ?? "";
  if (!rawBaseUrl) {
    throw new Error("OpenAPI spec has no servers[].url defined");
  }
  const baseUrl = rawBaseUrl.replace(/\/$/, "");
  const paths: Record<string, any> = spec.paths ?? {};
  const endpoints: Endpoint[] = [];

  for (const [path, pathItem] of Object.entries(paths)) {
    for (const method of HTTP_METHODS) {
      const operation = (pathItem as any)[method];
      if (!operation) continue;

      // Try application/json first, fall back to first available content type
      let bodySchema: unknown | undefined;
      const content = operation.requestBody?.content;
      if (content) {
        bodySchema = content["application/json"]?.schema
          ?? (Object.values(content)[0] as any)?.schema;
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
  const spec: unknown = await response.json();
  return parseOpenAPIFromJSON(spec);
}
