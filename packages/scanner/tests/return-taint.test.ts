import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { scanPath, scanSource } from "../src/index";
import { SqlInjectionAnalyzer } from "../src/analyzers/sql-injection";
import { CommandInjectionAnalyzer } from "../src/analyzers/command-injection";

// Taint that comes back out of a function through its return value (taint/returns.ts).

const dirs: string[] = [];
afterAll(() => dirs.forEach((d) => fs.rmSync(d, { recursive: true, force: true })));

function project(files: Record<string, string>): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "sh-return-"));
  dirs.push(dir);
  for (const [name, content] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(dir, name)), { recursive: true });
    fs.writeFileSync(path.join(dir, name), content);
  }
  return dir;
}
const sql = (dir: string) => scanPath(dir).results.flatMap((r) => r.findings).filter((f) => f.ruleId === "sql-injection");
const inline = (code: string) => scanSource(code, "app.js", [new SqlInjectionAnalyzer()]).findings;

describe("a value built from an argument and returned", () => {
  const route = (call: string) => `app.get("/u", (req, res) => {\n  ${call}\n  res.end();\n});\n`;

  it("is followed when the helper is in the same file", () => {
    const code = `function build(name) { return "SELECT * FROM users WHERE name = '" + name + "'"; }\n` + route(`const q = build(req.query.name); db.query(q);`);
    expect(inline(code)).toHaveLength(1);
  });

  it("is followed through a template literal, a ternary and an arrow function", () => {
    expect(inline(`const build = (n) => \`SELECT * FROM t WHERE n = '\${n}'\`;\n` + route(`const q = build(req.query.n); db.query(q);`))).toHaveLength(1);
    expect(inline(`function build(n, flag) { return flag ? "SELECT * FROM a WHERE n=" + n : "SELECT 1"; }\n` + route(`const q = build(req.query.n, true); db.query(q);`))).toHaveLength(1);
  });

  it("is followed through a chain of helpers and across files", () => {
    const dir = project({
      "package.json": JSON.stringify({ dependencies: { express: "4" } }),
      "lib/sql.js": `function where(name) { return "name = '" + name + "'"; }\nfunction select(name) { return "SELECT * FROM users WHERE " + where(name); }\nmodule.exports = { select };\n`,
      "app.js": `const { select } = require("./lib/sql");\nconst app = require("express")();\napp.get("/u", (req, res) => {\n  const q = select(req.query.name);\n  db.query(q);\n  res.end();\n});\n`,
    });
    expect(sql(dir)).toHaveLength(1);
  });

  it("is followed when the helper that runs the query receives the built value", () => {
    const dir = project({
      "package.json": JSON.stringify({ dependencies: { express: "4" } }),
      "repo.js": `function build(name) { return "SELECT * FROM users WHERE name = '" + name + "'"; }\nfunction find(name) { const q = build(name); return db.query(q); }\nmodule.exports = { find };\n`,
      "app.js": `const repo = require("./repo");\nconst app = require("express")();\napp.get("/u", (req, res) => res.json(repo.find(req.query.name)));\n`,
    });
    const found = sql(dir);
    expect(found).toHaveLength(1);
    expect(found[0]?.message).toContain("reaches the vulnerable call");
  });
});

describe("a function that returns request input by itself", () => {
  it("makes its call a source (getId(req))", () => {
    const code = `function getId(req) { return req.params.id; }\napp.get("/u/:id", (req, res) => {\n  const id = getId(req);\n  db.query("SELECT * FROM u WHERE id = " + id);\n});\n`;
    expect(inline(code)).toHaveLength(1);
    expect(inline(`function getId(req) { return req.params.id; }\napp.get("/u/:id", (req, res) => db.query("SELECT * FROM u WHERE id = " + getId(req)));\n`)).toHaveLength(1);
  });

  it("works through an alias inside the helper and across files", () => {
    const dir = project({
      "package.json": JSON.stringify({ dependencies: { express: "4" } }),
      "input.js": `function nameOf(req) { const n = req.query.name; return n; }\nmodule.exports = { nameOf };\n`,
      "app.js": `const { nameOf } = require("./input");\nconst app = require("express")();\napp.get("/u", (req, res) => {\n  db.query("SELECT * FROM users WHERE name = '" + nameOf(req) + "'");\n});\n`,
    });
    expect(sql(dir)).toHaveLength(1);
  });

  it("applies to every data-flow rule, not just SQL", () => {
    const code = `const { exec } = require("child_process");\nfunction cmdOf(req) { return req.body.cmd; }\napp.post("/run", (req, res) => { const c = cmdOf(req); exec(c); });\n`;
    expect(scanSource(code, "app.js", [new CommandInjectionAnalyzer()]).findings).toHaveLength(1);
  });
});

describe("what stays quiet", () => {
  const route = (call: string) => `app.get("/u", (req, res) => {\n  ${call}\n});\n`;

  it("a return value that went through another call is not followed (the call may clean it)", () => {
    expect(inline(`function build(n) { return escape(n); }\n` + route(`const q = build(req.query.n); db.query("SELECT " + q);`))).toHaveLength(0);
    expect(inline(`function build(n) { return parseInt(n); }\n` + route(`const q = build(req.query.n); db.query("SELECT * FROM t WHERE id = " + q);`))).toHaveLength(0);
  });

  it("a helper whose name says it cleans is never followed", () => {
    expect(inline(`function sanitizeName(n) { return n; }\n` + route(`const q = sanitizeName(req.query.n); db.query("SELECT '" + q + "'");`))).toHaveLength(0);
    expect(inline(`function validateId(n) { return n; }\n` + route(`const q = validateId(req.query.n); db.query("SELECT " + q);`))).toHaveLength(0);
    expect(inline(`function getId(req) { return req.params.id; }\nfunction toInt(x) { return x; }\n` + route(`const id = toInt(getId(req)); db.query("SELECT " + id);`))).toHaveLength(0);
  });

  it("a returned value used as a bound parameter is fine", () => {
    expect(inline(`function build(n) { return n; }\n` + route(`const q = build(req.query.n); db.query("SELECT * FROM t WHERE n = $1", [q]);`))).toHaveLength(0);
  });

  it("a return statement inside a nested callback is not the function's own return", () => {
    expect(inline(`function build(n) { [1].map(() => { return n; }); return "SELECT 1"; }\n` + route(`const q = build(req.query.n); db.query(q);`))).toHaveLength(0);
  });

  it("a helper that returns something unrelated to its argument is not followed", () => {
    expect(inline(`function build(n) { log(n); return "SELECT 1"; }\n` + route(`const q = build(req.query.n); db.query(q);`))).toHaveLength(0);
  });

  it("recursion and mutual recursion terminate", () => {
    const code = `function a(n) { return b(n) + "x"; }\nfunction b(n) { return a(n) + "y"; }\n` + route(`const q = a(req.query.n); db.query(q);`);
    expect(() => inline(code)).not.toThrow();
  });
});

describe("a helper that checks the value before handing it back (found by validating real projects)", () => {
  const route = (call: string) => `app.get("/u", (req, res) => {\n  ${call}\n});\n`;

  it("a ternary that tests the value with startsWith / includes is a guard", () => {
    const code = `function pickNext(v) { const n = typeof v === "string" ? v : ""; return n.startsWith("/") && !n.startsWith("//") ? n : "/app"; }\n` + route(`const next = pickNext(req.query.next); db.query("SELECT '" + next + "'");`);
    expect(inline(code)).toHaveLength(0);
  });

  it("an early return after an allowlist check is a guard, a presence check is not", () => {
    const guarded = `const ALLOWED = ["a", "b"];\nfunction pick(v) { if (!ALLOWED.includes(v)) return "a"; return v; }\n` + route(`const x = pick(req.query.v); db.query("SELECT '" + x + "'");`);
    expect(inline(guarded)).toHaveLength(0);
    const presence = `function build(n) { if (!n) return "SELECT 1"; return "SELECT * FROM t WHERE n = '" + n + "'"; }\n` + route(`const q = build(req.query.n); db.query(q);`);
    expect(inline(presence)).toHaveLength(1);
  });

  it("a helper whose name says it is safe or verifies is not followed", () => {
    expect(inline(`function safeValue(v) { return v; }\n` + route(`const x = safeValue(req.query.v); db.query("SELECT '" + x + "'");`))).toHaveLength(0);
    expect(inline(`function verifyToken(v) { return v; }\n` + route(`const x = verifyToken(req.query.v); db.query("SELECT '" + x + "'");`))).toHaveLength(0);
  });

  it("what a condition decides is not part of the value (token ? table[token] : undefined)", () => {
    const lookup = `const table = {};\nfunction lookup(token) { return token ? table[token] : undefined; }\n`;
    expect(inline(lookup + route(`const u = lookup(req.cookies.t); db.query("SELECT '" + u + "'");`))).toHaveLength(0);
    expect(inline(`function isAdmin(r) { return r === "admin"; }\n` + route(`const a = isAdmin(req.query.role); db.query("SELECT " + a);`))).toHaveLength(0);
  });
});
