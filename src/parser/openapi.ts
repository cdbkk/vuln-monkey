import type { Endpoint } from "../types.js";

const HTTP_METHODS = ["get", "post", "put", "patch", "delete"] as const;

export function parseOpenAPIFromJSON(spec: any): Endpoint[] {
  const baseUrl: string = spec.servers?.[0]?.url ?? "";
  const paths: Record<string, any> = spec.paths ?? {};
  const endpoints: Endpoint[] = [];

  for (const [path, pathItem] of Object.entries(paths)) {
    for (const method of HTTP_METHODS) {
      const operation = (pathItem as any)[method];
      if (!operation) continue;

      const bodySchema =
        operation.requestBody?.content?.["application/json"]?.schema;

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
  const spec: unknown = await response.json();
  return parseOpenAPIFromJSON(spec);
}
