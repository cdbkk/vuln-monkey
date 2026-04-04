import type { Endpoint, Vulnerability, AttackPayload } from "../types.js";

// Schema-independent universal attack payloads.
//
// The LLM payload generator can return zero payloads when the endpoint body
// schema is too minimal for it to build creative mutations ({"dryRun": true},
// a handful of flat string fields, etc). On a public API, "no payloads" is
// the worst possible answer, because the most interesting finding is usually
// "anyone can call this without auth."
//
// This fallback runs whenever parsePayloads returns an empty array. It never
// returns empty itself - it deterministically produces a baseline set of
// probes that work regardless of body shape.

const PRIVILEGE_ESCALATION_FIELDS = {
  isAdmin: true,
  is_admin: true,
  admin: true,
  role: "admin",
  roles: ["admin", "superuser"],
  is_superuser: true,
  is_staff: true,
  permissions: ["*"],
  user_id: 1,
  userId: 1,
  owner_id: 1,
  tenant_id: 1,
} as const;

function withoutAuthHeaders(
  headers: Record<string, string>
): Record<string, string> {
  const result: Record<string, string> = {};
  for (const [k, v] of Object.entries(headers)) {
    const lower = k.toLowerCase();
    if (lower === "authorization" || lower === "x-api-key" || lower === "apikey" || lower === "api-key") {
      continue;
    }
    result[k] = v;
  }
  return result;
}

function mergeBody(base: unknown, extra: Record<string, unknown>): unknown {
  if (base && typeof base === "object" && !Array.isArray(base)) {
    return { ...(base as Record<string, unknown>), ...extra };
  }
  return extra;
}

/**
 * Generate a deterministic baseline set of attack payloads that do not depend
 * on the endpoint body schema. Always returns at least 8 payloads.
 *
 * This is the last-resort safety net: if the LLM payload generator returns
 * empty (which happens with minimal body schemas), these universal probes run
 * instead, so every scanned endpoint gets at least the common auth-bypass
 * and mass-assignment variants tested.
 */
export function synthesizeFallbackPayloads(
  endpoint: Endpoint,
  vulnerabilities: Vulnerability[]
): AttackPayload[] {
  const { method, url, headers, body } = endpoint;
  const hasAuth = endpoint.auth.type !== "none";
  const payloads: AttackPayload[] = [];

  // 1. No-auth call: strip any auth headers, reuse original body.
  // This is the most important probe - it catches unauthenticated public
  // endpoints, which is a HIGH/CRITICAL finding in almost every real audit.
  payloads.push({
    name: "Fallback: Auth Bypass - No Credentials",
    vulnerability: "auth bypass",
    method,
    url,
    headers: withoutAuthHeaders(headers),
    body,
  });

  // 2. Invalid-auth call: provide a clearly-bogus token. Some endpoints
  // accept any non-empty bearer token as valid due to skipped verification.
  if (hasAuth) {
    payloads.push({
      name: "Fallback: Auth Bypass - Invalid Token",
      vulnerability: "auth bypass",
      method,
      url,
      headers: {
        ...withoutAuthHeaders(headers),
        Authorization: "Bearer invalid_fallback_probe_token",
      },
      body,
    });
  }

  // 3. Mass assignment with privilege escalation fields injected.
  payloads.push({
    name: "Fallback: Mass Assignment - Privilege Fields",
    vulnerability: "mass assignment",
    method,
    url,
    headers,
    body: mergeBody(body, PRIVILEGE_ESCALATION_FIELDS),
  });

  // 4. Mass assignment with empty body - reveals whether defaults leak.
  if (method !== "GET" && method !== "DELETE") {
    payloads.push({
      name: "Fallback: Mass Assignment - Empty Body",
      vulnerability: "mass assignment",
      method,
      url,
      headers,
      body: {},
    });
  }

  // 5. Info disclosure via malformed JSON - triggers parser error messages
  // that often leak framework version, stack traces, file paths.
  if (method !== "GET" && method !== "DELETE") {
    payloads.push({
      name: "Fallback: Info Disclosure - Malformed JSON",
      vulnerability: "information disclosure",
      method,
      url,
      headers: { ...headers, "Content-Type": "application/json" },
      // Sentinel string - the executor will pass this through as raw body
      // for text/json endpoints; the server's JSON parser error is the signal.
      body: "{invalid_json_fallback_probe",
    });
  }

  // 6. HTTP method override - some frameworks expose different auth paths
  // depending on method. POST endpoints sometimes also answer GET.
  const SWAP: Record<string, AttackPayload["method"]> = {
    POST: "GET",
    PUT: "GET",
    PATCH: "GET",
    DELETE: "GET",
    GET: "POST",
  };
  const swapped = SWAP[method];
  if (swapped) {
    payloads.push({
      name: `Fallback: Auth Bypass - HTTP Method Override (${method} -> ${swapped})`,
      vulnerability: "auth bypass",
      method: swapped,
      url,
      headers,
      body: swapped === "GET" ? undefined : body,
    });
  }

  // 7. Header injection with SQL-like payload - catches endpoints that
  // read custom headers into queries without parameterization.
  payloads.push({
    name: "Fallback: Injection - Header SQL Sentinel",
    vulnerability: "injection",
    method,
    url,
    headers: {
      ...headers,
      "X-User-Id": "1' OR '1'='1",
      "X-Forwarded-For": "127.0.0.1, 1' OR '1'='1",
    },
    body,
  });

  // 8. Path traversal appended to URL - catches endpoints that concatenate
  // path segments into filesystem reads. Use URL-encoded dots so neither
  // the URL constructor nor the JS fetch layer normalizes the traversal
  // away before the request lands on the server. Servers that decode
  // percent-encoding after normalizing are vulnerable; this is the real
  // bypass pattern, not raw ../../.
  try {
    const u = new URL(url);
    const suffix = "/%2E%2E/%2E%2E/%2E%2E/etc/passwd";
    // Build the URL as a raw string to bypass URL.pathname normalization.
    const base = `${u.protocol}//${u.host}${u.pathname.replace(/\/$/, "")}`;
    const traversalUrl = `${base}${suffix}${u.search}`;
    payloads.push({
      name: "Fallback: Injection - Path Traversal",
      vulnerability: "injection",
      method,
      url: traversalUrl,
      headers,
      body,
    });
  } catch {
    // URL parsing failed - skip this probe, we still have 7+ others
  }

  // 9. Oversized body - tests rate limits, body size caps, and overflow.
  // Only for methods that accept a body.
  if (method !== "GET" && method !== "DELETE") {
    const overflow = "A".repeat(10_000);
    payloads.push({
      name: "Fallback: Overflow - Large Payload",
      vulnerability: "overflow",
      method,
      url,
      headers,
      body: mergeBody(body, { overflow_probe: overflow }),
    });
  }

  // Tag payloads with any vulnerability types the LLM identified, so the
  // report still cites the LLM's analysis even though the payloads are fallback.
  if (vulnerabilities.length > 0) {
    const vulnTypes = vulnerabilities.map((v) => v.type).join(", ");
    for (const p of payloads) {
      p.name = `${p.name} [LLM-identified: ${vulnTypes}]`;
    }
  }

  return payloads;
}
