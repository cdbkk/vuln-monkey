import type { Endpoint } from "../types.js";

const VALID_METHODS = new Set(["GET", "POST", "PUT", "PATCH", "DELETE"]);
const API_KEY_HEADERS = ["x-api-key", "api-key", "apikey"];

export function parseCurl(command: string): Endpoint {
  // Strip backslash-newline continuations before tokenizing
  const raw = command.replace(/^curl\s+/, "").replace(/\\\n\s*/g, " ").trim();

  let method = "GET";
  let explicitMethod = false;
  const headers: Record<string, string> = {};
  let body: unknown | undefined;
  let url = "";
  let queryMode = false;
  const dataParts: string[] = [];

  // Tokenize respecting quotes and backslash escapes
  const tokens: string[] = [];
  let current = "";
  let inQuote: string | null = null;
  let escaped = false;

  for (const char of raw) {
    if (escaped) {
      current += char;
      escaped = false;
      continue;
    }

    if (char === "\\") {
      if (inQuote === "'") {
        // Single quotes don't support escapes in shell
        current += char;
      } else {
        escaped = true;
      }
      continue;
    }

    if (inQuote) {
      if (char === inQuote) {
        inQuote = null;
      } else {
        current += char;
      }
    } else if (char === "'" || char === '"') {
      inQuote = char;
    } else if (char === " ") {
      if (current) tokens.push(current);
      current = "";
    } else {
      current += char;
    }
  }
  if (current) tokens.push(current);

  let i = 0;
  while (i < tokens.length) {
    const token = tokens[i];

    if (token === "-X" || token === "--request") {
      if (i + 1 >= tokens.length) break;
      method = tokens[++i].toUpperCase();
      explicitMethod = true;
    } else if (token.startsWith("-X") && token.length > 2) {
      method = token.slice(2).toUpperCase();
      explicitMethod = true;
    } else if (token === "-H" || token === "--header") {
      if (i + 1 >= tokens.length) break;
      const headerStr = tokens[++i];
      const colonIdx = headerStr.indexOf(":");
      if (colonIdx > 0) {
        const key = headerStr.slice(0, colonIdx).trim().toLowerCase();
        const val = headerStr.slice(colonIdx + 1).replace(/[\r\n]/g, "").trim();
        headers[key] = val;
      }
    } else if (token === "-u" || token === "--user") {
      if (i + 1 >= tokens.length) break;
      headers["authorization"] = `Basic ${Buffer.from(tokens[++i]).toString("base64")}`;
    } else if (token === "-G") {
      queryMode = true;
    } else if (token === "-d" || token === "--data" || token === "--data-raw" || token === "--data-binary") {
      if (i + 1 >= tokens.length) break;
      dataParts.push(tokens[++i]);
    } else if (token.startsWith("http://") || token.startsWith("https://")) {
      url = token;
    }
    // Silently skip unknown flags (-v, --compressed, -L, etc.)

    i++;
  }

  if (!url) {
    throw new Error("No URL found in curl command");
  }

  if (dataParts.length > 0) {
    const dataStr = dataParts.join("&");
    if (queryMode) {
      const separator = url.includes("?")
        ? url.endsWith("?") || url.endsWith("&") ? "" : "&"
        : "?";
      url = `${url}${separator}${dataStr}`;
      if (!explicitMethod) method = "GET";
    } else {
      try {
        body = JSON.parse(dataStr);
      } catch {
        body = dataStr;
      }
      if (!explicitMethod && method === "GET") method = "POST";
    }
  }

  // Validate method
  if (!VALID_METHODS.has(method)) {
    throw new Error(`Unsupported HTTP method: ${method}`);
  }

  // Detect auth
  const authHeader = headers["authorization"] || "";
  let auth: Endpoint["auth"] = { type: "none" };

  if (authHeader.toLowerCase().startsWith("bearer ")) {
    auth = { type: "bearer", value: authHeader.slice(7) };
  } else if (authHeader.toLowerCase().startsWith("basic ")) {
    auth = { type: "basic", value: authHeader.slice(6) };
  } else {
    const apiKeyHeader = API_KEY_HEADERS.find((header) => headers[header] !== undefined);
    if (apiKeyHeader) {
      const value = headers[apiKeyHeader];
      auth = { type: "apikey", headerName: apiKeyHeader, ...(value ? { value } : {}) };
    }
  }

  return {
    method: method as Endpoint["method"],
    url,
    headers,
    body,
    auth,
  };
}
