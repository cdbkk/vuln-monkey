import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import type { Report } from "../types.js";
import { generateReportFilename } from "./filename.js";

export async function writeJSONReport(report: Report, outputDir: string): Promise<string> {
  await mkdir(outputDir, { recursive: true });

  const filename = generateReportFilename(report.timestamp, "json");
  const filePath = join(outputDir, filename);

  await writeFile(filePath, JSON.stringify(report, null, 2), "utf-8");
  return filePath;
}
