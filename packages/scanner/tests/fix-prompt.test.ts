import * as os from "os";
import * as path from "path";
import {
  Finding,
  RULE_IDS,
  ScanSummary,
  fenced,
  fixPromptFor,
  scanSource,
  toFixPrompt,
  toHtml,
  toMarkdown,
} from "../src/index";
import { HardcodedSecretAnalyzer } from "../src/analyzers/hardcoded-secret";

const root = path.join(os.tmpdir(), "proj");
const finding = (overrides: Partial<Finding> = {}): Finding => ({
  ruleId: "sql-injection",
  severity: "critical",
  confidence: "medium",
  message: "User-controlled input ('id') flows into a SQL query without parameterization.",
  location: { file: path.join(root, "src", "users.js"), startLine: 12, startColumn: 3, endLine: 12, endColumn: 50 },
  sourceSnippet: "req.query.id",
  sinkSnippet: 'db.query("SELECT * FROM u WHERE id = " + id)',
  ...overrides,
});
const summaryOf = (...findings: Finding[]): ScanSummary => ({
  filesScanned: 1,
  findingsCount: findings.length,
  durationMs: 1,
  results: [{ file: path.join(root, "src", "users.js"), findings }],
});

describe("fixPromptFor", () => {
  it("names the rule, the place, the code and how to fix it", () => {
    const prompt = fixPromptFor(finding(), { relativeTo: root });
    expect(prompt).toContain("Rule: sql-injection (critical)");
    expect(prompt).toContain("Where: src/users.js, line 12");
    expect(prompt).toContain("db.query(");
    expect(prompt).toContain("parameterized queries");
    expect(prompt).toContain("Show the exact changes");
  });

  it("has fix guidance for every rule the scanner can report", () => {
    for (const ruleId of RULE_IDS) {
      const prompt = fixPromptFor(finding({ ruleId }), { relativeTo: root });
      const guidance = prompt.split("How to fix: ")[1]?.split("\n")[0] ?? "";
      expect(guidance.length).toBeGreaterThan(40);
    }
  });

  it("never contains a secret: it is built from the already redacted fields", () => {
    const token = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8";
    const result = scanSource(`const k = "${token}";`, "app.js", [new HardcodedSecretAnalyzer()]);
    const summary = { filesScanned: 1, findingsCount: 1, durationMs: 1, results: [result] };
    const prompts = [toFixPrompt(summary), fixPromptFor(result.findings[0] as Finding)];
    for (const prompt of prompts) {
      expect(prompt).not.toContain(token);
      expect(prompt).not.toContain(token.slice(0, 12));
      expect(prompt).toContain("Do NOT write the real value");
      expect(prompt).toContain("revoked");
    }
  });
});

describe("toFixPrompt", () => {
  it("is empty when there is nothing to fix", () => {
    expect(toFixPrompt(summaryOf())).toBe("");
  });

  it("lists the most severe issues first and states the requirements once", () => {
    const prompt = toFixPrompt(summaryOf(finding({ severity: "low", ruleId: "csrf" }), finding({ severity: "critical" })), {
      relativeTo: root,
    });
    expect(prompt.indexOf("sql-injection")).toBeLessThan(prompt.indexOf("csrf"));
    expect(prompt).toContain("## Issue 1");
    expect(prompt).toContain("## Issue 2");
    expect(prompt.match(/Requirements for every fix:/g)).toHaveLength(1);
  });

  it("caps the number of issues and says how many were left out", () => {
    const many = Array.from({ length: 20 }, (_, i) => finding({ location: { ...finding().location, startLine: i + 1 } }));
    const prompt = toFixPrompt(summaryOf(...many), { maxFindings: 5 });
    expect(prompt.match(/## Issue/g)).toHaveLength(5);
    expect(prompt).toContain("15 more issue(s) not included");
  });
});

describe("fenced code blocks", () => {
  it("uses a fence longer than any backtick run inside, so content cannot break out", () => {
    expect(fenced("plain")).toBe("```text\nplain\n```");
    const nasty = "before\n```\n</details>\n@everyone\n[click](http://evil)\n``````\nafter";
    const block = fenced(nasty);
    const fence = block.split("\n")[0]?.replace("text", "") ?? "";
    expect(fence.length).toBeGreaterThan(6);
    expect(block.endsWith(fence)).toBe(true);
    // The only line that is exactly the fence is the last one: nothing inside can close it early.
    expect(block.split("\n").filter((line) => line === fence)).toHaveLength(1);
  });
});

describe("prompt in reports", () => {
  it("the pull request comment has a collapsed prompt block that attacker text cannot escape", () => {
    const hostile = finding({ message: "Bad ``` fence </details> @everyone [x](http://evil) <script>1</script>" });
    const md = toMarkdown(summaryOf(hostile), { relativeTo: root });
    expect(md).toContain("<details><summary>🤖 Fix with AI");
    expect(md).toContain("</details>");
    // Everything hostile sits inside a fence longer than the ``` it contains.
    const fenceLine = md.split("\n").find((l) => /^`{4,}text$/.test(l));
    expect(fenceLine).toBeDefined();
    expect(toMarkdown(summaryOf(hostile), { relativeTo: root, fixPrompt: false })).not.toContain("<details>");
    expect(toMarkdown(summaryOf(), { relativeTo: root })).not.toContain("<details>");
  });

  it("the HTML report has a copy button per finding and one for all, with the prompt escaped", () => {
    const html = toHtml(summaryOf(finding({ sinkSnippet: 'x" onmouseover="alert(1)' })), root);
    expect(html).toContain('class="copy"');
    expect(html).toContain('class="copy-all"');
    expect(html).toContain("Copy prompt for my AI assistant");
    expect(html).not.toMatch(/data-prompt="[^"]*" onmouseover="alert/);
    expect(html).toContain("&quot; onmouseover=&quot;alert(1)");
  });
});
