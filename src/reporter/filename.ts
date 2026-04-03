export function generateReportFilename(timestamp: string, ext: string): string {
  const safe = timestamp.replace(/:/g, "-");
  const suffix = Math.random().toString(36).slice(2, 8);
  return `vuln-monkey-${safe}-${suffix}.${ext}`;
}
