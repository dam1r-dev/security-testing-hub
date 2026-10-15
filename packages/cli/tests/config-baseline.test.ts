import { spawnSync } from "child_process";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";

jest.setTimeout(60_000);

const bin = path.resolve(__dirname, "../bin/security-hub.js");

const SQL_ROUTE = [
  "const express = require('express');",
  "const app = express();",
  "app.get('/user', (req, res) => {",
  '  db.query("SELECT * FROM users WHERE id = " + req.query.id);',
  "});",
  "",
].join("\n");
const CSRF_ROUTE = "const express = require('express');\nconst app = express();\napp.post('/delete', (req, res) => { res.send('ok'); });\n";

function project(files: Record<string, string>): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "hub-cli-config-"));
  for (const [name, text] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(dir, name)), { recursive: true });
    fs.writeFileSync(path.join(dir, name), text);
  }
  return dir;
}

function hub(args: string[]): { code: number; out: string; err: string } {
  const result = spawnSync(process.execPath, [bin, ...args], { encoding: "utf8" });
  return { code: result.status ?? -1, out: result.stdout, err: result.stderr };
}

function findings(args: string[]): { ruleId: string; severity: string }[] {
  const { out } = hub(["scan", ...args, "--format", "json"]);
  return JSON.parse(out).results.flatMap((r: { findings: { ruleId: string; severity: string }[] }) => r.findings);
}

describe("security-hub scan with .security-hub.json", () => {
  it("uses the project's severity and failOn, and flags win over the file", () => {
    const dir = project({ "app.js": SQL_ROUTE, "post.js": CSRF_ROUTE, ".security-hub.json": '{"severity": "high", "failOn": "critical"}' });
    const shown = findings([dir]);
    expect(shown.length).toBeGreaterThan(0);
    expect(shown.every((f) => ["high", "critical"].includes(f.severity))).toBe(true);
    expect(hub(["scan", dir]).code).toBe(1); // the SQL injection is critical: failOn from the file
    expect(hub(["scan", dir, "--fail-on", "critical", "--severity", "critical"]).code).toBe(1);
    // `--no-config`: everything is reported again and nothing fails
    expect(findings([dir, "--no-config"]).length).toBeGreaterThan(shown.length);
    expect(hub(["scan", dir, "--no-config"]).code).toBe(0);
  });

  it("says when a rule is switched off, and refuses a file with a typo", () => {
    const dir = project({ "app.js": SQL_ROUTE, ".security-hub.json": '{"disable": ["sql-injection"]}' });
    const run = hub(["scan", dir]);
    expect(run.out).toContain("1 finding(s) not shown: their rules are disabled in .security-hub.json.");
    expect(findings([dir]).some((f) => f.ruleId === "sql-injection")).toBe(false);

    const typo = project({ "app.js": SQL_ROUTE, ".security-hub.json": '{"disabel": []}' });
    const failed = hub(["scan", typo]);
    expect(failed.code).toBe(2);
    expect(failed.err).toContain('unknown setting "disabel"');

    const elsewhere = path.join(project({ "other.json": '{"disable": ["sql-injection"]}' }), "other.json");
    expect(findings([dir, "--config", elsewhere]).some((f) => f.ruleId === "sql-injection")).toBe(false);
    expect(hub(["scan", dir, "--config", path.join(dir, "missing.json")]).code).toBe(2);
  });
});

describe("security-hub baseline", () => {
  it("records today's findings; scans then show only new ones and fail only on those", () => {
    const dir = project({ "app.js": SQL_ROUTE });
    expect(hub(["scan", dir, "--fail-on", "high"]).code).toBe(1);

    const made = hub(["baseline", dir]);
    expect(made.code).toBe(0);
    expect(made.out).toContain("Saved 1 existing finding(s)");
    expect(fs.existsSync(path.join(dir, ".security-hub-baseline.json"))).toBe(true);

    const quiet = hub(["scan", dir, "--fail-on", "high"]);
    expect(quiet.code).toBe(0); // the old finding no longer fails the check
    expect(quiet.out).toContain("0 finding(s)");
    expect(quiet.out).toContain("1 existing finding(s) hidden by the baseline");

    fs.writeFileSync(path.join(dir, "new.js"), SQL_ROUTE.replace("users", "orders"));
    const withNew = hub(["scan", dir, "--fail-on", "high"]);
    expect(withNew.code).toBe(1);
    expect(withNew.out).toContain("new.js");
    expect(withNew.out).not.toContain("app.js:");

    // the baseline can be turned off, and a fixed finding is reported as a stale entry
    expect(findings([dir, "--no-baseline"])).toHaveLength(2);
    fs.writeFileSync(path.join(dir, "app.js"), "const fixed = true;\n");
    expect(hub(["scan", dir]).out).toContain("1 baseline entry no longer match anything");
  });

  it("has nothing to record in a clean project, and refuses a damaged baseline file", () => {
    const clean = project({ "ok.js": "const a = 1;\n" });
    expect(hub(["baseline", clean]).out).toContain("nothing to record");
    expect(fs.existsSync(path.join(clean, ".security-hub-baseline.json"))).toBe(false);

    const dir = project({ "app.js": SQL_ROUTE, ".security-hub-baseline.json": "{ nope" });
    const run = hub(["scan", dir]);
    expect(run.code).toBe(2);
    expect(run.err).toContain("not valid JSON");
  });
});
