import type { Finding } from "../types.js";

const SEVERITY_WEIGHTS: Record<string, number> = {
  critical: 25,
  high: 15,
  medium: 5,
  low: 2,
};

export function calculateRiskScore(findings: Pick<Finding, "severity">[]): number {
  const raw = findings.reduce((sum, f) => sum + (SEVERITY_WEIGHTS[f.severity] || 0), 0);
  return Math.min(raw, 100);
}

export function getRiskRating(score: number): "Fail" | "Needs Attention" | "Acceptable" {
  if (score > 70) return "Fail";
  if (score >= 40) return "Needs Attention";
  return "Acceptable";
}
