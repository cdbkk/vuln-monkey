import { isRecord, resolveLocalRef } from "./openapi-references.js";

type RequestBodyInfo = {
  body?: unknown;
  bodySchema?: unknown;
  contentType?: string;
};

function getSchemaExample(schema: unknown): unknown | undefined {
  if (!isRecord(schema)) return undefined;
  if ("example" in schema) return schema.example;
  if ("default" in schema) return schema.default;
  return undefined;
}

function getExampleValue(spec: Record<string, unknown>, example: unknown): unknown | undefined {
  const resolved = resolveLocalRef(spec, example);
  if (isRecord(resolved) && "value" in resolved) return resolved.value;
  return undefined;
}

function getBodyExample(
  spec: Record<string, unknown>,
  mediaType: Record<string, unknown>,
  schema: unknown
): unknown | undefined {
  if ("example" in mediaType) return mediaType.example;

  const examples = isRecord(mediaType.examples) ? mediaType.examples : undefined;
  if (examples) {
    for (const example of Object.values(examples)) {
      const value = getExampleValue(spec, example);
      if (value !== undefined) return value;
    }
  }

  return getSchemaExample(schema);
}

export function getRequestBody(
  spec: Record<string, unknown>,
  operation: Record<string, unknown>,
  parameters: Record<string, unknown>[]
): RequestBodyInfo {
  const reqBody = resolveLocalRef(spec, operation.requestBody);
  if (isRecord(reqBody)) {
    const content = isRecord(reqBody.content) ? reqBody.content : undefined;
    if (content) {
      const selected = isRecord(content["application/json"])
        ? ["application/json", content["application/json"]] as const
        : Object.entries(content).find((entry): entry is [string, Record<string, unknown>] =>
          isRecord(entry[1])
        );
      if (selected) {
        const [contentType, mediaType] = selected;
        const bodySchema = resolveLocalRef(spec, mediaType.schema);
        const body = getBodyExample(spec, mediaType, bodySchema);
        return {
          contentType,
          ...(body !== undefined ? { body } : {}),
          ...(bodySchema !== undefined ? { bodySchema } : {}),
        };
      }
    }
  }

  const bodyParameter = parameters.find((parameter) => parameter.in === "body");
  if (!bodyParameter) return {};

  const bodySchema = resolveLocalRef(spec, bodyParameter.schema);
  const body = "example" in bodyParameter
    ? bodyParameter.example
    : getSchemaExample(bodySchema);
  return {
    ...(body !== undefined ? { body } : {}),
    ...(bodySchema !== undefined ? { bodySchema } : {}),
  };
}
