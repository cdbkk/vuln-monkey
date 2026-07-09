import { AttackPayloadSchema, VulnerabilitySchema } from "../types.js";
import type { Endpoint, Vulnerability, AttackPayload } from "../types.js";

const VULN_TYPES = [
  "IDOR",
  "BOLA",
  "type juggling",
  "mass assignment",
  "rate limiting bypass",
  "auth bypass",
  "injection",
  "overflow",
  "race conditions",
  "excessive data exposure",
  "CORS misconfiguration",
  "information disclosure",
];

function formatJson(value: unknown): string {
  if (value === undefined) return "none";
  return JSON.stringify(value, null, 2) ?? "none";
}

function authHeaderName(auth: Endpoint["auth"]): string {
  if (auth.type === "bearer" || auth.type === "basic") return "Authorization";
  if (auth.type === "apikey") return auth.headerName ?? "X-API-Key";
  return "none";
}

function formatAuth(endpoint: Endpoint): string {
  if (endpoint.auth.type === "none") return "none";
  const credential = endpoint.auth.value ? "credential provided" : "no credential value provided";
  return `${endpoint.auth.type} via ${authHeaderName(endpoint.auth)} (${credential})`;
}

export function buildAnalysisPrompt(endpoint: Endpoint): string {
  const auth = formatAuth(endpoint);
  const headers = formatJson(endpoint.headers);
  const body = formatJson(endpoint.body);
  const bodySchema = formatJson(endpoint.bodySchema);

  return `You are a security expert analyzing an API endpoint for vulnerabilities.

Endpoint:
  Method: ${endpoint.method}
  URL: ${endpoint.url}
  Auth: ${auth}
  Headers: ${headers}
  Body: ${body}
  Body schema: ${bodySchema}

Analyze this endpoint and identify up to 5 of the most likely vulnerabilities from this list:
${VULN_TYPES.join(", ")}

Return ONLY a JSON array (no explanation) with up to 5 objects, each having:
- type: the vulnerability type (string)
- description: specific description of how the vulnerability applies to this endpoint (string)
- severity: one of "critical", "high", "medium", "low"

Example format:
\`\`\`json
[
  {
    "type": "IDOR",
    "description": "The endpoint uses a user-controlled ID without ownership verification",
    "severity": "high"
  }
]
\`\`\``;
}

export function buildPayloadPrompt(
  endpoint: Endpoint,
  vulnerabilities: Vulnerability[]
): string {
  const vulnSummary = vulnerabilities
    .map((v) => `- ${v.type}: ${v.description}`)
    .join("\n");

  return `You are a security expert generating attack payloads for an API endpoint.

Endpoint:
  Method: ${endpoint.method}
  URL: ${endpoint.url}
  Auth: ${formatAuth(endpoint)}
  Headers: ${formatJson(endpoint.headers)}
  Body: ${formatJson(endpoint.body)}
  Body schema: ${formatJson(endpoint.bodySchema)}

Vulnerabilities found:
${vulnSummary}

Generate 8-10 attack payloads per vulnerability as complete HTTP requests.

Return ONLY a JSON array (no explanation) where each object has:
- name: descriptive name for the attack (string)
- vulnerability: the vulnerability type being tested (string)
- method: HTTP method, one of "GET", "POST", "PUT", "PATCH", "DELETE"
- url: full URL including any manipulated path/query params (string)
- headers: object of HTTP headers (object)
- body: request body (any type, omit if not needed)

Example format:
\`\`\`json
[
  {
    "name": "IDOR - Access another user's resource",
    "vulnerability": "IDOR",
    "method": "GET",
    "url": "https://api.example.com/users/2",
    "headers": { "Authorization": "Bearer <attacker_token>" },
    "body": null
  }
]
\`\`\``;
}

function extractJsonArray(raw: string): unknown[] {
  const fenced = raw.match(/```(?:json)?\s*([\s\S]*?)```/);
  const candidate = fenced ? fenced[1].trim() : raw.trim();

  const start = candidate.indexOf("[");
  const end = candidate.lastIndexOf("]");
  if (start === -1 || end === -1) return [];

  try {
    const parsed = JSON.parse(candidate.slice(start, end + 1));
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

const VALID_SEVERITIES = new Set(["critical", "high", "medium", "low"]);
const ASCII_CONTROL_CHARS = /[\x00-\x1F]/g;

function cleanString(value: unknown): string {
  return String(value ?? "").replace(ASCII_CONTROL_CHARS, "");
}

function cleanHeaders(value: unknown): Record<string, string> | null | undefined {
  if (value === undefined || value === null) return undefined;
  if (typeof value !== "object" || Array.isArray(value)) return null;

  const headers: Record<string, string> = {};
  for (const [key, headerValue] of Object.entries(value)) {
    if (typeof headerValue !== "string") return null;
    headers[key] = headerValue;
  }
  return headers;
}

export function parseVulnerabilities(
  raw: string,
  endpoint: string
): Vulnerability[] {
  const items = extractJsonArray(raw);
  return items.flatMap((item) => {
    if (typeof item !== "object" || item === null || Array.isArray(item)) return [];

    const severity = cleanString((item as Record<string, unknown>)["severity"]);
    const parsed = VulnerabilitySchema.safeParse({
      type: cleanString((item as Record<string, unknown>)["type"]),
      description: cleanString((item as Record<string, unknown>)["description"]),
      severity: VALID_SEVERITIES.has(severity)
        ? (severity as Vulnerability["severity"])
        : "medium",
      endpoint: cleanString(endpoint),
    });
    return parsed.success ? [parsed.data] : [];
  });
}

export function parsePayloads(raw: string): AttackPayload[] {
  const items = extractJsonArray(raw);

  return items.flatMap((item) => {
    if (typeof item !== "object" || item === null || Array.isArray(item)) return [];

    const record = item as Record<string, unknown>;
    const headers = cleanHeaders(record["headers"]);
    if (headers === null) return [];

    const parsed = AttackPayloadSchema.safeParse({
      name: cleanString(record["name"]),
      vulnerability: cleanString(record["vulnerability"]),
      method: cleanString(record["method"]),
      url: cleanString(record["url"]),
      headers,
      body: record["body"] !== undefined ? record["body"] : undefined,
    });
    return parsed.success ? [parsed.data] : [];
  });
}
