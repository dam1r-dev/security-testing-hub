import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { computeScore, coverageNotes, scanPath, toHtml, toMarkdown } from "../src";

jest.setTimeout(60_000);

function project(files: Record<string, string>): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "hub-coverage-"));
  for (const [name, body] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(dir, name)), { recursive: true });
    fs.writeFileSync(path.join(dir, name), body);
  }
  return dir;
}

const VULNERABLE = "app.get('/x', (req, res) => { exec('echo ' + req.query.a); });\n";

describe("what a scan covers (0.8)", () => {
  it("an empty folder is not rated: nothing was analysed, so 100/100 would say nothing", () => {
    const summary = scanPath(project({ "README.md": "# hi\n" }), { config: false });
    expect(summary.coverage).toEqual({ analyzed: 0, skipped: 0, parseErrors: 0, unsupported: {} });
    const score = computeScore(summary);
    expect(score.rated).toBe(false);
    expect(coverageNotes(summary)[0]).toMatch(/nothing in this project's code was checked/);
    expect(toMarkdown(summary)).toMatch(/not rated/);
    expect(toMarkdown(summary)).not.toMatch(/🎉|100\/100/);
    expect(toHtml(summary)).toMatch(/Not rated/);
  });

  it("a project in a language without rules says which one, and how many files", () => {
    const summary = scanPath(project({ "main.go": "package main\n", "util/a.go": "package util\n", "app.rb": "puts 1\n", "src/App.vue": "<script>1</script>\n" }), { config: false });
    expect(summary.coverage?.unsupported).toEqual({ Go: 2, Ruby: 1, "Vue components": 1 });
    expect(computeScore(summary).rated).toBe(false);
    expect(coverageNotes(summary).join(" ")).toMatch(/Found 4 files in languages without rules \(Go 2, Ruby 1, Vue components 1\)/);
  });

  it("a mixed project is rated, and the note says how much was left out", () => {
    const summary = scanPath(project({ "server.js": VULNERABLE, "tools/gen.go": "package main\n", "tools/more.go": "package main\n" }), { config: false });
    expect(summary.coverage).toMatchObject({ analyzed: 1, skipped: 0, unsupported: { Go: 2 } });
    expect(computeScore(summary).rated).toBe(true);
    expect(coverageNotes(summary)).toEqual([expect.stringMatching(/2 files in languages without rules were not checked \(Go 2\).*1 JavaScript, TypeScript, Python or PHP file that was analysed/)]);
    expect(toMarkdown(summary)).toMatch(/> 2 files in languages without rules/);
  });

  it("skipped and half-parsed files are counted, not hidden", () => {
    const dir = project({
      "ok.js": VULNERABLE,
      "bundle.js": `var a=${"x+1;".repeat(20000)}`,
      "public/assets/plugins/lib/lib.js": "/*!\n * Lib v1\n * Released under the MIT license\n */\nvar x = 1;\n",
      "broken.js": "function (((( {{{ ]]]\n",
    });
    const coverage = scanPath(dir, { config: false }).coverage;
    expect(coverage).toMatchObject({ analyzed: 2, skipped: 2, parseErrors: 1 });
    const notes = coverageNotes(scanPath(dir, { config: false }));
    expect(notes.join(" ")).toMatch(/2 files skipped.*1 file could not be parsed completely/);
  });

  it("a clean, fully read project has no notes", () => {
    const summary = scanPath(project({ "a.js": "const x = 1;\n", "b.py": "x = 1\n" }), { config: false });
    expect(coverageNotes(summary)).toEqual([]);
    expect(computeScore(summary)).toMatchObject({ rated: true, value: 100 });
  });

  it("a summary made without coverage (older callers) is rated as before", () => {
    expect(computeScore({ filesScanned: 0, findingsCount: 0, results: [], durationMs: 0 }).rated).toBe(true);
  });
});
