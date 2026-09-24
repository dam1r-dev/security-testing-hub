import { toHtml } from "../src/output/html";
import { ScanSummary, Finding } from "../src/types";

function mockFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    ruleId: "xss",
    severity: "high",
    confidence: "medium",
    message: "a message",
    location: { file: "app.js", startLine: 1, startColumn: 1, endLine: 1, endColumn: 1 },
    sourceSnippet: "",
    sinkSnippet: "",
    ...overrides,
  };
}

function mockSummary(findings: Finding[], parseError?: string): ScanSummary {
  return {
    filesScanned: 1,
    findingsCount: findings.length,
    durationMs: 5,
    results: [{ file: "app.js", findings, parseError }],
  };
}

describe("toHtml", () => {
  it("produces a well-formed HTML document", () => {
    const html = toHtml(mockSummary([mockFinding()]));
    expect(html).toMatch(/^<!DOCTYPE html>/);
    expect(html).toContain("<html");
    expect(html).toContain("</html>");
    expect(html).toContain("Security Testing Hub");
  });

  it("escapes HTML in finding text instead of injecting it raw (the report itself must not be XSS-able)", () => {
    const html = toHtml(
      mockSummary([
        mockFinding({
          message: `<script>alert(1)</script>`,
          sinkSnippet: `res.send("<img src=x onerror=alert(1)>")`,
        }),
      ]),
    );
    expect(html).not.toContain("<script>alert(1)</script>");
    expect(html).not.toContain("<img src=x onerror=alert(1)>");
    expect(html).toContain("&lt;script&gt;");
    expect(html).toContain("&lt;img src=x onerror=alert(1)&gt;");
  });

  it("shows the score value and severity counts", () => {
    const findings = Array.from({ length: 3 }, () => mockFinding({ severity: "critical", confidence: "high" }));
    const html = toHtml(mockSummary(findings));
    expect(html).toContain(">40<"); // 100 - 20*3
    expect(html).toContain("At risk");
  });

  it("renders a clean success state with no findings", () => {
    const html = toHtml(mockSummary([]));
    expect(html).toContain("No findings");
    expect(html).toContain(">100<");
    expect(html).toContain("Good");
  });

  it("surfaces parse warnings", () => {
    const html = toHtml(mockSummary([], "Source has syntax errors; results may be incomplete."));
    expect(html).toContain("parse issues");
    expect(html).toContain("Source has syntax errors");
  });
});
