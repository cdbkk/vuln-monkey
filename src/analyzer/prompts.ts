import type { Endpoint, Vulnerability, AttackPayload } from "../types.js";

const VULN_TYPES = [
  "IDOR",
  "type juggling",
  "mass assignment",
  "rate limiting bypass",
  "auth bypass",
  "injection",
  "overflow",
  "race conditions",
];

export function buildAnalysisPrompt(endpoint: Endpoint): string {
  const authType = endpoint.auth.type;
  const bodySchema = endpoint.bodySchema
    ? JSON.stringify(endpoint.bodySchema, null, 2)
    : "none";

  return `You are a security expert analyzing an API endpoint for vulnerabilities.

Endpoint:
  Method: ${endpoint.method}
  URL: ${endpoint.url}
  Auth type: ${authType}
  Body schema: ${bodySchema}

Analyze this endpoint and identify exactly 5 vulnerabilities from this list:
${VULN_TYPES.join(", ")}

Return ONLY a JSON array (no explanation) with exactly 5 objects, each having:
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
  Auth type: ${endpoint.auth.type}

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

export function parseVulnerabilities(
  raw: string,
  endpoint: string
): Vulnerability[] {
  const items = extractJsonArray(raw);
  return items
    .filter(
      (item): item is Record<string, unknown> =>
        typeof item === "object" && item !== null
    )
    .map((item) => ({
      type: String(item["type"] ?? ""),
      description: String(item["description"] ?? ""),
      severity: VALID_SEVERITIES.has(String(item["severity"]))
        ? (String(item["severity"]) as Vulnerability["severity"])
        : "medium",
      endpoint,
    }));
}

export function parsePayloads(raw: string): AttackPayload[] {
  const items = extractJsonArray(raw);
  const VALID_METHODS = new Set(["GET", "POST", "PUT", "PATCH", "DELETE"]);

  return items
    .filter(
      (item): item is Record<string, unknown> =>
        typeof item === "object" && item !== null
    )
    .filter((item) => VALID_METHODS.has(String(item["method"])))
    .map((item) => ({
      name: String(item["name"] ?? ""),
      vulnerability: String(item["vulnerability"] ?? ""),
      method: String(item["method"]) as AttackPayload["method"],
      url: String(item["url"] ?? ""),
      headers:
        typeof item["headers"] === "object" &&
        item["headers"] !== null &&
        !Array.isArray(item["headers"])
          ? (item["headers"] as Record<string, string>)
          : {},
      body: item["body"] !== undefined ? item["body"] : undefined,
    }));
}
