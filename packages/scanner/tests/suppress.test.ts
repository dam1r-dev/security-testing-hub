import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { scanPath, scanSource } from "../src/index";
import { compileIgnorePatterns, parseIgnoreFile } from "../src/suppress";

const SQLI = `app.get("/u", (req, res) => {\n  db.query("SELECT * FROM u WHERE n = '" + req.query.n + "'");\n});`;

describe("inline security-hub-ignore comments", () => {
  it("reports the finding when there is no comment", () => {
    const result = scanSource(SQLI, "app.js");
    expect(result.findings.map((f) => f.ruleId)).toEqual(["sql-injection"]);
    expect(result.suppressed).toBeUndefined();
  });

  it("hides a finding with a trailing comment on the same line, and counts it", () => {
    const source = SQLI.replace("req.query.n + \"'\");", "req.query.n + \"'\"); // security-hub-ignore");
    const result = scanSource(source, "app.js");
    expect(result.findings).toHaveLength(0);
    expect(result.suppressed).toBe(1);
  });

  it("hides a finding with a comment on the line above (// and /* */)", () => {
    for (const comment of ["// security-hub-ignore", "/* security-hub-ignore */", "// security-hub-ignore -- trusted admin tool"]) {
      const source = SQLI.replace("  db.query", `  ${comment}\n  db.query`);
      expect(scanSource(source, "app.js").findings).toHaveLength(0);
    }
  });

  it("can be limited to named rules: only those are hidden", () => {
    const source = SQLI.replace("  db.query", "  // security-hub-ignore xss, sql-injection\n  db.query");
    expect(scanSource(source, "app.js").findings).toHaveLength(0);
    const otherRule = SQLI.replace("  db.query", "  // security-hub-ignore xss\n  db.query");
    expect(scanSource(otherRule, "app.js").findings).toHaveLength(1);
  });

  it("treats free text after the directive as a reason, not as rule names", () => {
    const source = SQLI.replace("  db.query", "  // security-hub-ignore internal admin tool\n  db.query");
    expect(scanSource(source, "app.js").findings).toHaveLength(0);
  });

  it("does not let a trailing comment on unrelated code above cover the next line", () => {
    const source = SQLI.replace("  db.query", "  const x = 1; // security-hub-ignore\n  db.query");
    expect(scanSource(source, "app.js").findings).toHaveLength(1);
  });

  it("does not hide a finding that is two lines below the comment", () => {
    const source = SQLI.replace("  db.query", "  // security-hub-ignore\n  const y = 2;\n  db.query");
    expect(scanSource(source, "app.js").findings).toHaveLength(1);
  });
});

describe("ignore patterns", () => {
  const ignored = (patterns: string[], file: string) => compileIgnorePatterns(patterns)(file);

  it("matches names at any depth when the pattern has no slash", () => {
    expect(ignored(["fixtures"], "src/fixtures/a.js")).toBe(true);
    expect(ignored(["fixtures"], "fixtures/a.js")).toBe(true);
    expect(ignored(["*.generated.ts"], "src/api/x.generated.ts")).toBe(true);
    expect(ignored(["*.generated.ts"], "src/api/x.ts")).toBe(false);
  });

  it("anchors patterns that contain a slash to the scan root", () => {
    expect(ignored(["scripts/legacy"], "scripts/legacy/a.js")).toBe(true);
    expect(ignored(["scripts/legacy"], "src/scripts/legacy/a.js")).toBe(false);
    expect(ignored(["/scripts"], "scripts/a.js")).toBe(true);
    expect(ignored(["/scripts"], "src/scripts/a.js")).toBe(false);
  });

  it("supports ** and ?, and a trailing slash for directories", () => {
    expect(ignored(["src/**/legacy.js"], "src/a/b/legacy.js")).toBe(true);
    expect(ignored(["src/**/legacy.js"], "src/legacy.js")).toBe(true);
    expect(ignored(["file?.js"], "file1.js")).toBe(true);
    expect(ignored(["old/"], "old/x.js")).toBe(true);
    expect(ignored(["old/"], "old")).toBe(false);
  });

  it("does not treat regex characters in a pattern as regex", () => {
    expect(ignored(["a+b.js"], "aab.js")).toBe(false);
    expect(ignored(["a+b.js"], "a+b.js")).toBe(true);
  });

  it("parses an ignore file: comments and blank lines are skipped", () => {
    expect(parseIgnoreFile("# legacy code\n\nscripts/\r\n  *.mock.js  \n")).toEqual(["scripts/", "*.mock.js"]);
  });
});

describe("scanPath: ignore file, --ignore patterns and includeTests", () => {
  let dir: string;
  const write = (rel: string, source: string) => {
    fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
    fs.writeFileSync(path.join(dir, rel), source);
  };
  const scannedFiles = (summary: ReturnType<typeof scanPath>) =>
    summary.results.map((r) => path.relative(dir, r.file).split(path.sep).join("/")).sort();

  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "sh-ignore-"));
    write("src/app.js", "const a = 1;\n");
    write("scripts/legacy/old.js", "const b = 2;\n");
    write("src/api.mock.js", "const c = 3;\n");
    write("tests/app.test.js", "const d = 4;\n");
    write("src/util.spec.ts", "export const e = 5;\n");
  });
  afterEach(() => fs.rmSync(dir, { recursive: true, force: true }));

  it("skips test folders and spec files by default, and scans them with includeTests", () => {
    expect(scannedFiles(scanPath(dir))).toEqual(["scripts/legacy/old.js", "src/api.mock.js", "src/app.js"]);
    expect(scannedFiles(scanPath(dir, { includeTests: true }))).toEqual([
      "scripts/legacy/old.js",
      "src/api.mock.js",
      "src/app.js",
      "src/util.spec.ts",
      "tests/app.test.js",
    ]);
  });

  it("reads .security-hub-ignore from the scanned folder", () => {
    write(".security-hub-ignore", "# generated and legacy code\nscripts/\n*.mock.js\n");
    expect(scannedFiles(scanPath(dir))).toEqual(["src/app.js"]);
  });

  it("applies the ignore option on top of the file", () => {
    write(".security-hub-ignore", "scripts/\n");
    expect(scannedFiles(scanPath(dir, { ignore: ["*.mock.js"] }))).toEqual(["src/app.js"]);
  });

  it("totals suppressed findings across files", () => {
    write(
      "src/routes.js",
      `app.get("/a", (req, res) => {\n  // security-hub-ignore\n  db.query("SELECT " + req.query.a);\n  db.query("SELECT " + req.query.b); // security-hub-ignore sql-injection\n});`,
    );
    const summary = scanPath(dir);
    expect(summary.suppressedCount).toBe(2);
    expect(summary.findingsCount).toBe(0);
  });
});
