import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import {
  applyBaseline,
  BASELINE_FILE_NAME,
  BaselineError,
  ConfigError,
  createBaseline,
  loadBaseline,
  loadConfig,
  parseBaseline,
  parseConfig,
  scanPath,
  serializeBaseline,
  toMarkdown,
} from "../src";

jest.setTimeout(30_000);

const SQL_ROUTE = [
  "const express = require('express');",
  "const app = express();",
  "app.get('/user', (req, res) => {",
  '  db.query("SELECT * FROM users WHERE id = " + req.query.id);',
  "});",
  "",
].join("\n");

function project(files: Record<string, string>): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "hub-config-"));
  for (const [name, text] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(dir, name)), { recursive: true });
    fs.writeFileSync(path.join(dir, name), text);
  }
  return dir;
}

const SECRET_VALUE = "wZ9qLm3vXr7TnB2kYd5sPa8c";

describe(".security-hub.json", () => {
  it("accepts the documented settings", () => {
    const config = parseConfig('{"$schema": "x", "ignore": ["legacy/", "scripts/**"], "disable": ["csrf", "csrf", "idor"], "severity": "medium", "failOn": "high", "includeTests": true}');
    expect(config).toEqual({ ignore: ["legacy/", "scripts/**"], disable: ["csrf", "idor"], severity: "medium", failOn: "high", includeTests: true });
    expect(parseConfig("{}")).toEqual({ ignore: [], disable: [] });
    expect(parseConfig("﻿{}")).toEqual({ ignore: [], disable: [] }); // a Windows editor's byte-order mark
  });

  it.each([
    ["{", /not valid JSON/],
    ["[]", /one JSON object/],
    ['{"disabel": ["csrf"]}', /unknown setting "disabel"\. Known settings: ignore, disable/],
    ['{"disable": ["csrff"]}', /unknown rule "csrff"\. Rules: sql-injection/],
    ['{"disable": "csrf"}', /list of rule ids/],
    ['{"severity": "severe"}', /"severity" must be one of low, medium, high, critical/],
    ['{"failOn": 3}', /"failOn" must be one of/],
    ['{"ignore": [""]}', /list of path patterns/],
    ['{"includeTests": "yes"}', /true or false/],
  ])("rejects %s with a message that says what is wrong", (text, message) => {
    expect(() => parseConfig(text, ".security-hub.json")).toThrow(ConfigError);
    expect(() => parseConfig(text, ".security-hub.json")).toThrow(message);
  });

  it("is read from the scanned folder, and a named file that is missing is an error", () => {
    const dir = project({ ".security-hub.json": '{"disable": ["csrf"]}' });
    expect(loadConfig(dir).config.disable).toEqual(["csrf"]);
    expect(loadConfig(dir).file).toBe(path.join(dir, ".security-hub.json"));
    expect(loadConfig(project({})).config).toEqual({ ignore: [], disable: [] }); // no file: the defaults
    expect(() => loadConfig(dir, path.join(dir, "nope.json"))).toThrow(/Config file not found/);
  });

  it("switches rules off and says how many findings that hid", () => {
    const files = { "app.js": SQL_ROUTE, "config.js": `module.exports = { jwtSecret: "${SECRET_VALUE}" };\n` };
    const plain = scanPath(project(files));
    expect(plain.results.flatMap((r) => r.findings).map((f) => f.ruleId).sort()).toEqual(["hardcoded-secret", "sql-injection"]);
    expect(plain.disabledCount).toBeUndefined();

    const off = scanPath(project({ ...files, ".security-hub.json": '{"disable": ["hardcoded-secret"]}' }));
    expect(off.results.flatMap((r) => r.findings).map((f) => f.ruleId)).toEqual(["sql-injection"]);
    expect(off.disabledCount).toBe(1);
    expect(off.findingsCount).toBe(1);
    expect(toMarkdown(off)).toContain("1 finding(s) are not listed: their rules are disabled in `.security-hub.json`.");
  });

  it("skips paths and can include tests; options and `config: false` win over the file", () => {
    const files = { "app.js": SQL_ROUTE, "legacy/old.js": SQL_ROUTE, "tests/a.js": SQL_ROUTE };
    const dir = project({ ...files, ".security-hub.json": '{"ignore": ["legacy/"], "includeTests": true}' });
    const scanned = (summary: ReturnType<typeof scanPath>): string[] => summary.results.map((r) => path.relative(dir, r.file).split(path.sep).join("/")).sort();
    expect(scanned(scanPath(dir))).toEqual(["app.js", "tests/a.js"]); // legacy skipped, tests included
    expect(scanned(scanPath(dir, { includeTests: false }))).toEqual(["app.js"]); // the caller's choice wins
    expect(scanned(scanPath(dir, { config: false }))).toEqual(["app.js", "legacy/old.js"]); // the file is ignored
  });

  it("a bad file stops the scan with the message, it is never silently skipped", () => {
    expect(() => scanPath(project({ "app.js": SQL_ROUTE, ".security-hub.json": '{"disable": ["csrff"]}' }))).toThrow(/unknown rule "csrff"/);
  });
});

describe("baseline", () => {
  it("hides what is there today, reports what is new", () => {
    const dir = project({ "app.js": SQL_ROUTE, "config.js": `module.exports = { jwtSecret: "${SECRET_VALUE}" };\n` });
    const baseline = createBaseline(scanPath(dir), dir);
    expect(baseline.findings).toHaveLength(2);

    const again = applyBaseline(scanPath(dir), baseline, dir);
    expect(again.findingsCount).toBe(0);
    expect(again.baselinedCount).toBe(2);
    expect(again.staleBaselineCount).toBe(0);

    fs.writeFileSync(path.join(dir, "new.js"), SQL_ROUTE.replace("users", "orders"));
    const withNew = applyBaseline(scanPath(dir), baseline, dir);
    expect(withNew.results.flatMap((r) => r.findings).map((f) => path.basename(f.location.file))).toEqual(["new.js"]);
    expect(withNew.baselinedCount).toBe(2);
  });

  it("survives edits above the finding: the line number is not what it is matched by", () => {
    const dir = project({ "app.js": SQL_ROUTE });
    const baseline = createBaseline(scanPath(dir), dir);
    fs.writeFileSync(path.join(dir, "app.js"), `// a new comment\n// and another\n${SQL_ROUTE}`);
    const after = applyBaseline(scanPath(dir), baseline, dir);
    expect(after.findingsCount).toBe(0);
    expect(after.baselinedCount).toBe(1);
  });

  it("the same line flagged again is a new finding; a fixed one makes its entry stale", () => {
    const dir = project({ "app.js": SQL_ROUTE });
    const baseline = createBaseline(scanPath(dir), dir);
    const twice = SQL_ROUTE.replace("});\n", '});\napp.get("/again", (req, res) => {\n  db.query("SELECT * FROM users WHERE id = " + req.query.id);\n});\n');
    fs.writeFileSync(path.join(dir, "app.js"), twice);
    const added = applyBaseline(scanPath(dir), baseline, dir);
    expect(added.findingsCount).toBe(1); // the copy is not covered by the one entry
    expect(added.baselinedCount).toBe(1);

    fs.writeFileSync(path.join(dir, "app.js"), "const x = 1;\n"); // fixed
    const fixed = applyBaseline(scanPath(dir), baseline, dir);
    expect(fixed.findingsCount).toBe(0);
    expect(fixed.baselinedCount ?? 0).toBe(0);
    expect(fixed.staleBaselineCount).toBe(1);
    expect(toMarkdown(fixed)).toContain("1 baseline entry no longer match anything");
  });

  it("matches the same project in another folder (paths are relative)", () => {
    const one = project({ "src/app.js": SQL_ROUTE });
    const two = project({ "src/app.js": SQL_ROUTE });
    const baseline = createBaseline(scanPath(one), one);
    expect(applyBaseline(scanPath(two), baseline, two).findingsCount).toBe(0);
  });

  it("never holds a secret, a part of it, or a hash of it: a secret is matched by the name it is assigned to", () => {
    const dir = project({ "config.js": `module.exports = { jwtSecret: "${SECRET_VALUE}" };\n` });
    const text = serializeBaseline(createBaseline(scanPath(dir), dir));
    expect(text).not.toContain(SECRET_VALUE);
    expect(text).not.toContain(SECRET_VALUE.slice(0, 4));
    // changing the secret's value (rotating it) does not make the old finding "new", only the name counts
    fs.writeFileSync(path.join(dir, "config.js"), 'module.exports = { jwtSecret: "Xk4mQ8vT1nZr6LbW3yHd9sCe" };\n');
    expect(applyBaseline(scanPath(dir), parseBaseline(text), dir).findingsCount).toBe(0);
  });

  it("is a file in the project: load, round trip, and clear errors for a damaged one", () => {
    const dir = project({ "app.js": SQL_ROUTE });
    const baseline = createBaseline(scanPath(dir), dir);
    fs.writeFileSync(path.join(dir, BASELINE_FILE_NAME), serializeBaseline(baseline));
    expect(loadBaseline(dir)?.baseline).toEqual(baseline);
    expect(loadBaseline(project({}))).toBeUndefined();
    expect(() => loadBaseline(dir, path.join(dir, "missing.json"))).toThrow(/Baseline file not found/);
    expect(() => parseBaseline("{")).toThrow(BaselineError);
    expect(() => parseBaseline('{"version": 2, "findings": []}')).toThrow(/not a baseline file/);
    expect(() => parseBaseline('{"version": 1, "findings": [{"id": "../../etc"}]}')).toThrow(/no valid "id"/);
    // the file itself is never reported as a finding or scanned as source
    expect(scanPath(dir).results.some((r) => r.file.endsWith(BASELINE_FILE_NAME))).toBe(false);
  });
});
