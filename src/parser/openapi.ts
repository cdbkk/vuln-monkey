import type { Endpoint } from "../types.js";
import { readPublicUrl } from "../executor/public-http.js";
import {
  applyPathParameters,
  applyQueryParameters,
  getParameters,
  headersFromParameters,
} from "./openapi-parameters.js";
import { isRecord } from "./openapi-references.js";
import { getRequestBody } from "./openapi-request-body.js";
import {
  authFromParameters,
  authFromSecurity,
  headersFromAuth,
  mergeHeaders,
} from "./openapi-security.js";
import { getBaseUrl } from "./openapi-servers.js";

const HTTP_METHODS = ["get", "post", "put", "patch", "delete", "head", "options"] as const;
const OPENAPI_FETCH_TIMEOUT_MS = 30_000;

export function parseOpenAPIFromJSON(
  spec: Record<string, unknown>,
  sourceUrl?: string,
  credentialHeaders: Record<string, string> = {},
  credentialOrigins: string[] = []
): Endpoint[] {
  const paths = (spec.paths ?? {}) as Record<string, Record<string, unknown>>;
  const endpoints: Endpoint[] = [];
  const trustedCredentialOrigins = new Set(
    credentialOrigins.map((origin) => new URL(origin).origin)
  );

  for (const [path, pathItem] of Object.entries(paths)) {
    if (!isRecord(pathItem)) continue;
    for (const method of HTTP_METHODS) {
      const operation = pathItem[method];
      if (!isRecord(operation)) continue;

      const parameters = getParameters(spec, pathItem, operation);
      const { contentType, ...requestBody } = getRequestBody(spec, operation, parameters);
      const parameterHeaders = headersFromParameters(spec, parameters);
      const parameterAuth = authFromParameters(spec, parameters);
      const baseUrl = getBaseUrl(spec, pathItem, operation, sourceUrl);
      const trustedCredentials = trustedCredentialOrigins.has(new URL(baseUrl).origin)
        ? credentialHeaders
        : {};
      const security = authFromSecurity(spec, operation, {
        ...parameterHeaders,
        ...trustedCredentials,
      });
      const auth = parameterAuth.type !== "none" ? parameterAuth : security.auth;
      const url = applyQueryParameters(
        `${baseUrl}${applyPathParameters(path, spec, parameters)}`,
        spec,
        parameters
      );

      const endpoint: Endpoint = {
        method: method.toUpperCase() as Endpoint["method"],
        url,
        headers: mergeHeaders(
          parameterHeaders,
          contentType ? { "Content-Type": contentType } : {},
          headersFromAuth(auth),
          security.headers
        ),
        auth,
        credentialHeaderNames: [...new Set([
          ...security.credentialHeaderNames,
          ...(parameterAuth.type === "bearer" || parameterAuth.type === "basic"
            ? ["Authorization"]
            : parameterAuth.type === "apikey" && parameterAuth.headerName
              ? [parameterAuth.headerName]
              : []),
        ])],
        ...requestBody,
      };

      endpoints.push(endpoint);
    }
  }

  if (endpoints.length === 0) getBaseUrl(spec, undefined, undefined, sourceUrl);

  return endpoints;
}

export async function parseOpenAPIFromURL(
  url: string,
  credentialHeaders: Record<string, string> = {},
  credentialOrigins: string[] = [],
  allowPrivate = false
): Promise<Endpoint[]> {
  const spec = JSON.parse(
    await readPublicUrl(url, OPENAPI_FETCH_TIMEOUT_MS, allowPrivate)
  ) as Record<string, unknown>;
  return parseOpenAPIFromJSON(spec, url, credentialHeaders, credentialOrigins);
}
