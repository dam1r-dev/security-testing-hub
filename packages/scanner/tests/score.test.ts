import { computeScore } from "../src/output/score";
import { ScanSummary, Finding } from "../src/types";

function mockFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    ruleId: "sql-injection",
    severity: "critical",
    confidence: "high",
    message: "test",
    location: { file: "app.js", startLine: 1, startColumn: 1, endLine: 1, endColumn: 1 },
    sourceSnippet: "",
    sinkSnippet: "",
    ...overrides,
  };
}

function mockSummary(findings: Finding[]): ScanSummary {
  return {
    filesScanned: 1,
    findingsCount: findings.length,
    durationMs: 1,
    results: [{ file: "app.js", findings }],
  };
}

describe("computeScore", () => {
  it("is 100/green with no findings", () => {
    const score = computeScore(mockSummary([]));
    expect(score.value).toBe(100);
    expect(score.color).toBe("green");
    expect(score.label).toBe("Good");
  });

  it("drops sharply for a single high-confidence critical finding", () => {
    const score = computeScore(mockSummary([mockFinding({ severity: "critical", confidence: "high" })]));
    expect(score.value).toBe(80); // 100 - 20*1.0
  });

  it("weighs low-confidence findings less than high-confidence ones", () => {
    const highConfidence = computeScore(mockSummary([mockFinding({ severity: "high", confidence: "high" })]));
    const lowConfidence = computeScore(mockSummary([mockFinding({ severity: "high", confidence: "low" })]));
    expect(lowConfidence.value).toBeGreaterThan(highConfidence.value);
  });

  it("never goes below 0", () => {
    const findings = Array.from({ length: 20 }, () => mockFinding({ severity: "critical", confidence: "high" }));
    const score = computeScore(mockSummary(findings));
    expect(score.value).toBe(0);
    expect(score.color).toBe("red");
    expect(score.label).toBe("At risk");
  });

  it("counts findings correctly by severity", () => {
    const score = computeScore(
      mockSummary([
        mockFinding({ severity: "critical" }),
        mockFinding({ severity: "critical" }),
        mockFinding({ severity: "high" }),
        mockFinding({ severity: "low" }),
      ]),
    );
    expect(score.bySeverity).toEqual({ critical: 2, high: 1, medium: 0, low: 1 });
    expect(score.totalFindings).toBe(4);
  });

  it("lands in the yellow band for a moderate number of findings", () => {
    const findings = Array.from({ length: 4 }, () => mockFinding({ severity: "high", confidence: "medium" }));
    const score = computeScore(mockSummary(findings));
    expect(score.value).toBeGreaterThanOrEqual(50);
    expect(score.value).toBeLessThan(80);
    expect(score.color).toBe("yellow");
  });
});
