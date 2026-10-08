import { execFileSync } from "child_process";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import {
  Finding,
  ScanSummary,
  annotationFor,
  changedFiles,
  filterSummary,
  scanPath,
  toGithubAnnotations,
  toSarif,
  toMarkdown,
} from "../src/index";

const finding = (overrides: Partial<Finding> = {}): Finding => ({
  ruleId: "sql-injection",
  severity: "critical",
  confidence: "medium",
  message: "User-controlled input ('id') flows into a SQL query without parameterization. Use bound parameters.",
  location: { file: path.join(os.tmpdir(), "proj", "src", "a.js"), startLine: 7, startColumn: 3, endLine: 7, endColumn: 40 },
  sourceSnippet: "req.query.id",
  sinkSnippet: "db.query(...)",
  ...overrides,
});

const summaryOf = (...findings: Finding[]): ScanSummary => {
  const byFile = new Map<string, Finding[]>();
  for (const f of findings) byFile.set(f.location.file, [...(byFile.get(f.location.file) ?? []), f]);
  return {
    filesScanned: byFile.size,
    findingsCount: findings.length,
    results: [...byFile].map(([file, fs_]) => ({ file, findings: fs_ })),
    durationMs: 1,
  };
};

describe("filterSummary", () => {
  const a = finding({ location: { ...finding().location, file: path.join(os.tmpdir(), "proj", "a.js") } });
  const b = finding({ severity: "medium", location: { ...finding().location, file: path.join(os.tmpdir(), "proj", "b.js") } });

  it("keeps only findings in the given files and counts what it left out", () => {
    const result = filterSummary(summaryOf(a, b), { files: [path.join(os.tmpdir(), "proj", "b.js")] });
    expect(result.findingsCount).toBe(1);
    expect(result.results.flatMap((r) => r.findings)).toEqual([b]);
    expect(result.filteredOutCount).toBe(1);
  });

  it("applies the minimum severity without counting those as 'other files'", () => {
    const result = filterSummary(summaryOf(a, b), { minSeverity: "high" });
    expect(result.findingsCount).toBe(1);
    expect(result.filteredOutCount).toBe(0);
  });

  it("returns the summary untouched when there is nothing to filter by", () => {
    const summary = summaryOf(a);
    expect(filterSummary(summary, {})).toBe(summary);
  });
});

describe("toMarkdown (pull request comment)", () => {
  it("renders score, counts and a table, with the marker the bot uses to update its comment", () => {
    const md = toMarkdown(summaryOf(finding(), finding({ severity: "medium", ruleId: "csrf" })), {
      relativeTo: path.join(os.tmpdir(), "proj"),
    });
    expect(md.startsWith("<!-- security-testing-hub-report -->")).toBe(true);
    expect(md).toMatch(/\d+\/100/);
    expect(md).toContain("critical **1**");
    expect(md).toContain("`sql-injection`");
    expect(md).toContain("`src/a.js:7`");
    expect(md.indexOf("sql-injection")).toBeLessThan(md.indexOf("csrf")); // most severe first
  });

  it("links a location when given a link base, and shows the cross-file target", () => {
    const md = toMarkdown(
      summaryOf(
        finding({
          message:
            "User-controlled input ('q') flows into a SQL query. The value is passed to find() and reaches the vulnerable call at services/q.js:8 (via find -> run).",
        }),
      ),
      { relativeTo: path.join(os.tmpdir(), "proj"), linkBase: "https://github.com/o/r/blob/abc123" },
    );
    expect(md).toContain("(https://github.com/o/r/blob/abc123/src/a.js#L7)");
    expect(md).toContain("→ `services/q.js:8`");
  });

  it("neutralises markdown, HTML and @-mentions that come from the scanned code", () => {
    const md = toMarkdown(
      summaryOf(finding({ message: "Input <img src=x onerror=alert(1)> reaches [click](http://evil) and pings @everyone | extra." })),
      // The table is what must neutralise text; the AI-prompt block holds raw text inside a code fence (see fix-prompt.test.ts).
      { fixPrompt: false },
    );
    expect(md).not.toContain("<img");
    expect(md).toContain("&lt;img");
    expect(md).not.toMatch(/(^|[^\\])\[click\]/);
    expect(md).toContain("\\@everyone");
    expect(md).toContain("\\| extra");
  });

  it("caps the number of rows and says how many are not shown", () => {
    const many = Array.from({ length: 12 }, (_, i) => finding({ location: { ...finding().location, startLine: i + 1 } }));
    const md = toMarkdown(summaryOf(...many), { maxRows: 5 });
    expect(md).toContain("…and 7 more.");
  });

  it("explains the scope and what was left out", () => {
    const md = toMarkdown({ ...summaryOf(), filteredOutCount: 3, suppressedCount: 2 }, { scopeNote: "Only changed files." });
    expect(md).toContain("No findings");
    expect(md).toContain("> Only changed files.");
    expect(md).toContain("3 more finding(s) in files this change does not touch");
    expect(md).toContain("2 finding(s) hidden");
  });
});

describe("GitHub annotations", () => {
  const root = path.join(os.tmpdir(), "proj");

  it("maps severity to error / warning / notice and uses a workspace-relative path", () => {
    expect(annotationFor(finding(), { relativeTo: root })).toMatch(/^::error file=src\/a\.js,line=7,col=3,endLine=7,title=sql-injection \(critical\)::/);
    expect(annotationFor(finding({ severity: "medium" }), { relativeTo: root })).toMatch(/^::warning /);
    expect(annotationFor(finding({ severity: "low" }), { relativeTo: root })).toMatch(/^::notice /);
  });

  it("cannot be used to smuggle a second workflow command", () => {
    const line = annotationFor(finding({ message: "ok\n::set-output name=x::pwned\r\n100%" }), { relativeTo: root });
    expect(line.split("\n")).toHaveLength(1);
    expect(line).toContain("%0A::set-output");
    expect(line).toContain("%25");
    const weirdPath = annotationFor(
      finding({ location: { ...finding().location, file: path.join(root, "a:b,c\n.js") } }),
      { relativeTo: root },
    );
    expect(weirdPath.split("\n")).toHaveLength(1);
    expect(weirdPath).toContain("file=a%3Ab%2Cc%0A.js");
  });

  it("emits one line per finding", () => {
    expect(toGithubAnnotations(summaryOf(finding(), finding()), { relativeTo: root })).toHaveLength(2);
  });
});

describe("changedFiles (git)", () => {
  let dir: string;
  const git = (...args: string[]) =>
    execFileSync("git", ["-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false", ...args], {
      cwd: dir,
      stdio: "pipe",
      encoding: "utf8",
    });
  const write = (rel: string, source: string) => {
    fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
    fs.writeFileSync(path.join(dir, rel), source);
  };
  const VULNERABLE = (name: string) => `app.get("/${name}", (req, res) => { db.query("SELECT " + req.query.${name}); });\n`;

  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "sh-git-"));
    git("init", "-q");
    git("checkout", "-q", "-b", "main");
    write("src/old.js", VULNERABLE("old"));
    write("src/stable.js", "const x = 1;\n");
    git("add", "-A");
    git("commit", "-q", "-m", "base");
    git("checkout", "-q", "-b", "feature");
    write("src/new.js", VULNERABLE("added"));
    write("src/stable.js", "const x = 2;\n");
    git("add", "-A");
    git("commit", "-q", "-m", "change");
    // main moves on after the branch point: those files are not part of "this PR".
    git("checkout", "-q", "main");
    write("src/main-only.js", "const y = 1;\n");
    git("add", "-A");
    git("commit", "-q", "-m", "main moves");
    git("checkout", "-q", "feature");
  });
  afterEach(() => fs.rmSync(dir, { recursive: true, force: true }));

  it("lists the files a pull request changes (merge-base diff), as absolute paths", () => {
    const files = changedFiles(dir, "main").map((f) => path.relative(dir, f).split(path.sep).join("/")).sort();
    expect(files).toEqual(["src/new.js", "src/stable.js"]);
    expect(changedFiles(dir, "main").every((f) => path.isAbsolute(f))).toBe(true);
  });

  it("works from a sub-folder of the repository", () => {
    const files = changedFiles(path.join(dir, "src"), "main").map((f) => path.basename(f)).sort();
    expect(files).toEqual(["new.js", "stable.js"]);
  });

  it("reports only findings in changed files but scans the whole project", () => {
    const summary = scanPath(dir);
    expect(summary.findingsCount).toBe(2); // old.js and new.js
    const narrowed = filterSummary(summary, { files: changedFiles(dir, "main") });
    expect(narrowed.results.flatMap((r) => r.findings).map((f) => path.basename(f.location.file))).toEqual(["new.js"]);
    expect(narrowed.filteredOutCount).toBe(1);
  });

  it("explains itself when the ref doesn't exist, and rejects option-like refs", () => {
    expect(() => changedFiles(dir, "no-such-branch")).toThrow(/Could not diff against "no-such-branch"/);
    expect(() => changedFiles(dir, "--output=x")).toThrow(/Invalid git ref/);
  });

  it("explains itself outside a git repository", () => {
    const plain = fs.mkdtempSync(path.join(os.tmpdir(), "sh-nogit-"));
    try {
      expect(() => changedFiles(plain, "main")).toThrow(/not inside a git repository/);
    } finally {
      fs.rmSync(plain, { recursive: true, force: true });
    }
  });
});

describe("SARIF paths for code scanning", () => {
  it("makes absolute paths relative to the repository root, and leaves relative ones alone", () => {
    const root = path.join(os.tmpdir(), "proj");
    const absolute = toSarif([{ file: "x", findings: [finding()] }], { relativeTo: root });
    const uri = (sarif: ReturnType<typeof toSarif>) => sarif.runs[0]?.results[0]?.locations[0]?.physicalLocation.artifactLocation.uri;
    expect(uri(absolute)).toBe("src/a.js");
    const relative = toSarif([{ file: "x", findings: [finding({ location: { ...finding().location, file: "./src/b.js" } })] }], {
      relativeTo: root,
    });
    expect(uri(relative)).toBe("src/b.js");
  });
});
