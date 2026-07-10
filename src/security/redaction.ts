export const REDACTED = "[REDACTED]";

const SENSITIVE_KEYS = new Set([
  "authorization",
  "proxyauthorization",
  "cookie",
  "setcookie",
  "xapikey",
  "xauthtoken",
  "apikey",
  "accesstoken",
  "refreshtoken",
  "token",
  "password",
  "passwd",
  "secret",
  "clientsecret",
  "credential",
  "session",
]);
const URL_KEYS = new Set(["url", "target", "endpoint"]);
const BODY_KEYS = new Set(["body", "responsebody"]);

function normalizedKey(key: string): string {
  return key.replace(/[^a-z0-9]/gi, "").toLowerCase();
}

function isSensitiveKey(key: string): boolean {
  const normalized = normalizedKey(key);
  return SENSITIVE_KEYS.has(normalized)
    || normalized.endsWith("token")
    || normalized.endsWith("password")
    || normalized.endsWith("secret");
}

export function redactUrl(value: string): string {
  try {
    const url = new URL(value);
    let changed = false;
    if (url.username) {
      url.username = REDACTED;
      changed = true;
    }
    if (url.password) {
      url.password = REDACTED;
      changed = true;
    }
    for (const key of url.searchParams.keys()) {
      if (isSensitiveKey(key)) {
        url.searchParams.set(key, REDACTED);
        changed = true;
      }
    }
    return changed ? url.toString() : value;
  } catch {
    return value;
  }
}

export function redactText(value: string): string {
  try {
    return JSON.stringify(redactValue(JSON.parse(value)));
  } catch {
    return value
      .replace(/\b(Bearer|Basic)\s+[^\s"']+/gi, `$1 ${REDACTED}`)
      .replace(
        /(["']?(?:access[_-]?token|refresh[_-]?token|api[_-]?key|password|secret)["']?\s*[:=]\s*["']?)[^\s,"'}]+/gi,
        `$1${REDACTED}`
      );
  }
}

export function redactValue(value: unknown, key = ""): unknown {
  if (isSensitiveKey(key)) return REDACTED;

  if (normalizedKey(key) === "headers" && typeof value === "object" && value !== null) {
    return Object.fromEntries(Object.keys(value).map((header) => [header, REDACTED]));
  }

  if (typeof value === "string") {
    const normalized = normalizedKey(key);
    if (URL_KEYS.has(normalized)) return redactUrl(value);
    if (BODY_KEYS.has(normalized)) return redactText(value);
    return value;
  }

  if (Array.isArray(value)) {
    return value.map((item) => redactValue(item));
  }

  if (typeof value === "object" && value !== null) {
    return Object.fromEntries(
      Object.entries(value).map(([childKey, childValue]) => [
        childKey,
        redactValue(childValue, childKey),
      ])
    );
  }

  return value;
}
