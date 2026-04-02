import type { Endpoint } from "../types.js";

export function parseCurl(command: string): Endpoint {
  const raw = command.replace(/^curl\s+/, "").trim();

  let method = "GET";
  const headers: Record<string, string> = {};
  let body: unknown | undefined;
  let url = "";

  // Tokenize respecting quotes
  const tokens: string[] = [];
  let current = "";
  let inQuote: string | null = null;

  for (const char of raw) {
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
      method = tokens[++i].toUpperCase();
    } else if (token === "-H" || token === "--header") {
      const headerStr = tokens[++i];
      const colonIdx = headerStr.indexOf(":");
      if (colonIdx > 0) {
        const key = headerStr.slice(0, colonIdx).trim().toLowerCase();
        const val = headerStr.slice(colonIdx + 1).trim();
        headers[key] = val;
      }
    } else if (token === "-d" || token === "--data" || token === "--data-raw") {
      const dataStr = tokens[++i];
      try {
        body = JSON.parse(dataStr);
      } catch {
        body = dataStr;
      }
      if (method === "GET") method = "POST";
    } else if (token.startsWith("http://") || token.startsWith("https://")) {
      url = token;
    }

    i++;
  }

  if (!url) {
    throw new Error("No URL found in curl command");
  }

  // Detect auth
  const authHeader = headers["authorization"] || "";
  let auth: Endpoint["auth"] = { type: "none" };

  if (authHeader.toLowerCase().startsWith("bearer ")) {
    auth = { type: "bearer", value: authHeader.slice(7) };
  } else if (authHeader.toLowerCase().startsWith("basic ")) {
    auth = { type: "basic", value: authHeader.slice(6) };
  }

  return {
    method: method as Endpoint["method"],
    url,
    headers,
    body,
    auth,
  };
}
