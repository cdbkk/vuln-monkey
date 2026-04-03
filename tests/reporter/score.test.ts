import { describe, it, expect } from "vitest";
import { calculateRiskScore, getRiskRating } from "../../src/reporter/score.js";

describe("calculateRiskScore", () => {
  it("returns 0 for no findings", () => {
    expect(calculateRiskScore([])).toBe(0);
  });

  it("scores one critical as 25", () => {
    expect(calculateRiskScore([{ severity: "critical" }])).toBe(25);
  });

  it("caps at 100", () => {
    const findings = Array(10).fill({ severity: "critical" });
    expect(calculateRiskScore(findings)).toBe(100);
  });

  it("sums mixed severities", () => {
    const findings = [
      { severity: "critical" },
      { severity: "high" },
      { severity: "low" },
    ];
    expect(calculateRiskScore(findings)).toBe(42);
  });

  it("scores medium severity as 5", () => {
    expect(calculateRiskScore([{ severity: "medium" }])).toBe(5);
  });

  it("handles unknown severity as 0", () => {
    expect(calculateRiskScore([{ severity: "unknown" as any }])).toBe(0);
  });
});

describe("getRiskRating", () => {
  it("returns Fail above 70", () => {
    expect(getRiskRating(71)).toBe("Fail");
  });

  it("returns Needs Attention for 40-70", () => {
    expect(getRiskRating(50)).toBe("Needs Attention");
  });

  it("returns Acceptable below 40", () => {
    expect(getRiskRating(39)).toBe("Acceptable");
  });

  it("returns Needs Attention at exactly 70", () => {
    expect(getRiskRating(70)).toBe("Needs Attention");
  });

  it("returns Needs Attention at exactly 40", () => {
    expect(getRiskRating(40)).toBe("Needs Attention");
  });

  it("returns Acceptable at 0", () => {
    expect(getRiskRating(0)).toBe("Acceptable");
  });
});
