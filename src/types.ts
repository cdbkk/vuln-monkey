import { z } from "zod";

export const EndpointSchema = z.object({
  method: z.enum(["GET", "POST", "PUT", "PATCH", "DELETE"]),
  url: z.string().url(),
  headers: z.record(z.string(), z.string()).default({}),
  body: z.unknown().optional(),
  bodySchema: z.unknown().optional(),
  auth: z.object({
    type: z.enum(["bearer", "basic", "apikey", "none"]),
    value: z.string().optional(),
    headerName: z.string().optional(),
  }).default({ type: "none" }),
});
export type Endpoint = z.infer<typeof EndpointSchema>;

export const SeveritySchema = z.enum(["critical", "high", "medium", "low"]);
export type Severity = z.infer<typeof SeveritySchema>;

export const VulnerabilitySchema = z.object({
  type: z.string(),
  description: z.string(),
  severity: SeveritySchema,
  endpoint: z.string(),
});
export type Vulnerability = z.infer<typeof VulnerabilitySchema>;

export const AttackPayloadSchema = z.object({
  name: z.string(),
  vulnerability: z.string(),
  method: z.enum(["GET", "POST", "PUT", "PATCH", "DELETE"]),
  url: z.string(),
  headers: z.record(z.string(), z.string()).default({}),
  body: z.unknown().optional(),
});
export type AttackPayload = z.infer<typeof AttackPayloadSchema>;

export const ResultClassification = z.enum([
  "pass",
  "suspicious",
  "error",
  "crash",
]);
export type ResultClassification = z.infer<typeof ResultClassification>;

export const ExecutionResultSchema = z.object({
  payload: AttackPayloadSchema,
  statusCode: z.number(),
  responseTime: z.number(),
  responseBody: z.string(),
  responseHeaders: z.record(z.string(), z.string()),
  classification: ResultClassification,
  finding: z.string().optional(),
});
export type ExecutionResult = z.infer<typeof ExecutionResultSchema>;

export const FindingSchema = z.object({
  title: z.string(),
  severity: SeveritySchema,
  endpoint: z.string(),
  description: z.string(),
  payload: AttackPayloadSchema,
  response: z.object({
    statusCode: z.number(),
    body: z.string(),
    responseTime: z.number(),
  }),
});
export type Finding = z.infer<typeof FindingSchema>;

export const ReportSchema = z.object({
  target: z.string(),
  timestamp: z.string(),
  endpointsScanned: z.number(),
  payloadsFired: z.number(),
  findings: z.array(FindingSchema),
  riskScore: z.number().min(0).max(100),
  riskRating: z.enum(["Fail", "Needs Attention", "Acceptable"]),
  model: z.string(),
  duration: z.number(),
});
export type Report = z.infer<typeof ReportSchema>;

export interface LLMProvider {
  analyze(endpoint: Endpoint): Promise<Vulnerability[]>;
  generatePayloads(
    endpoint: Endpoint,
    vulnerabilities: Vulnerability[]
  ): Promise<AttackPayload[]>;
}

export interface CLIOptions {
  spec?: string;
  model: "claude" | "gemini";
  output: string;
  concurrency: number;
  timeout: number;
  dryRun: boolean;
}
