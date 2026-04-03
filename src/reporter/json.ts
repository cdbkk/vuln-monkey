import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import type { Report } from "../types.js";

export async function writeJSONReport(report: Report, outputDir: string): Promise<string> {
  await mkdir(outputDir, { recursive: true });

  const timestamp = report.timestamp.replace(/:/g, "-");
  const suffix = Math.random().toString(36).slice(2, 8);
  const filename = `vuln-monkey-${timestamp}-${suffix}.json`;
  const filePath = join(outputDir, filename);

  await writeFile(filePath, JSON.stringify(report, null, 2), "utf-8");
  return filePath;
}
