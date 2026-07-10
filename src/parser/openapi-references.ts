export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function resolveLocalRef(spec: Record<string, unknown>, value: unknown): unknown {
  if (!isRecord(value)) return value;
  const ref = value.$ref;
  if (typeof ref !== "string" || !ref.startsWith("#/")) return value;

  let current: unknown = spec;
  for (const part of ref.slice(2).split("/")) {
    const key = part.replace(/~1/g, "/").replace(/~0/g, "~");
    if (!isRecord(current) || !(key in current)) return undefined;
    current = current[key];
  }
  return current;
}
