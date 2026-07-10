import { existsSync, realpathSync } from "node:fs";
import { dirname, isAbsolute, relative, resolve, sep } from "node:path";
import type { Finding } from "./types.js";

const MAX_CONCURRENCY = 100;
const MAX_TIMEOUT_MS = 2_147_483_647;
const SEVERITY_RANK = { low: 1, medium: 2, high: 3, critical: 4 } as const;

export type FailureSeverity = keyof typeof SEVERITY_RANK | "none";

export function collectOption(value: string, previous: string[]): string[] {
  return [...previous, value];
}

function positiveInteger(value: string, option: string, maximum: number): number {
  if (!/^[1-9]\d*$/.test(value)) throw new Error(`${option} must be a positive integer`);
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed)) throw new Error(`${option} must be a safe positive integer`);
  if (parsed > maximum) throw new Error(`${option} must be at most ${maximum}`);
  return parsed;
}

function headers(values: string[]): Record<string, string> {
  return Object.fromEntries(values.map((value) => {
    const separator = value.indexOf(":");
    if (separator <= 0) throw new Error(`--header must use "Name: value" format`);
    return [value.slice(0, separator).trim(), value.slice(separator + 1).trim()];
  }));
}

function origins(values: string[]): string[] {
  return values.map((value) => {
    try {
      const url = new URL(value);
      if (url.protocol !== "http:" && url.protocol !== "https:") throw new Error();
      return url.origin;
    } catch {
      throw new Error(`--credential-origin must be an http(s) origin`);
    }
  });
}

function failureSeverity(value: string): FailureSeverity {
  if (value === "none" || value in SEVERITY_RANK) return value as FailureSeverity;
  throw new Error(`--fail-on must be one of: none, low, medium, high, critical`);
}

function outputDirectory(value: string): string {
  const outputDir = resolve(value);
  let existingParent = outputDir;
  while (!existsSync(existingParent)) {
    const parent = dirname(existingParent);
    if (parent === existingParent) break;
    existingParent = parent;
  }

  const realOutputDir = resolve(
    realpathSync(existingParent),
    relative(existingParent, outputDir)
  );
  const sensitiveDirs = [
    "/etc", "/usr", "/bin", "/sbin", "/sys", "/proc", "/boot", "/root",
    process.env.SystemRoot,
  ]
    .filter((dir): dir is string => Boolean(dir))
    .map((dir) => existsSync(dir) ? realpathSync(dir) : dir);
  if (sensitiveDirs.some((dir) => {
    const child = relative(dir, realOutputDir);
    return child === "" || (child !== ".." && !child.startsWith(`..${sep}`) && !isAbsolute(child));
  })) {
    throw new Error(`Output path targets a sensitive system directory`);
  }
  return outputDir;
}

export function parseRuntimeOptions(options: {
  concurrency: string;
  timeout: string;
  header: string[];
  credentialOrigin: string[];
  failOn: string;
  output: string;
}): {
  concurrency: number;
  timeout: number;
  headerOverrides: Record<string, string>;
  credentialOrigins: string[];
  failOn: FailureSeverity;
  outputDir: string;
} {
  return {
    concurrency: positiveInteger(options.concurrency, "--concurrency", MAX_CONCURRENCY),
    timeout: positiveInteger(options.timeout, "--timeout", MAX_TIMEOUT_MS),
    headerOverrides: headers(options.header),
    credentialOrigins: origins(options.credentialOrigin),
    failOn: failureSeverity(options.failOn),
    outputDir: outputDirectory(options.output),
  };
}

export function reachesFailureThreshold(
  findings: Finding[],
  threshold: FailureSeverity
): boolean {
  return threshold !== "none"
    && findings.some((finding) => SEVERITY_RANK[finding.severity] >= SEVERITY_RANK[threshold]);
}
