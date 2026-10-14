import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { applyPlan, planFixes, renderPlan, scanPath } from "../src/index";

// Automatic fixes (src/fix): what they change, what they refuse to change, and that the result is really fixed.

const dirs: string[] = [];
afterAll(() => dirs.forEach((d) => fs.rmSync(d, { recursive: true, force: true })));

function project(files: Record<string, string>, dependencies: Record<string, string> = { express: "4", pg: "8" }): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "sh-fix-"));
  dirs.push(dir);
  fs.writeFileSync(path.join(dir, "package.json"), JSON.stringify({ dependencies }));
  for (const [name, content] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(dir, name)), { recursive: true });
    fs.writeFileSync(path.join(dir, name), content);
  }
  return dir;
}
const read = (dir: string, name: string) => fs.readFileSync(path.join(dir, name), "utf8");
const plan = (dir: string, only?: string[]) => planFixes(scanPath(dir), dir, { only });
const fixedText = (dir: string, name: string, only?: string[]) => {
  const p = plan(dir, only);
  applyPlan(p);
  return read(dir, name);
};
const count = (dir: string, ruleId: string) => scanPath(dir).results.flatMap((r) => r.findings).filter((f) => f.ruleId === ruleId).length;

const route = (query: string) => `app.get("/u", (req, res) => {\n  const name = req.query.name;\n  const age = req.query.age;\n  db.query(${query});\n  res.end();\n});\n`;

describe("fix: SQL injection becomes bound parameters", () => {
  it("a template literal: numbers and quoted strings become $1, $2 with the values in an array (pg)", () => {
    const dir = project({ "app.js": route("`SELECT * FROM users WHERE name = '${name}' AND age > ${age}`") });
    const text = fixedText(dir, "app.js", ["sql-injection"]);
    expect(text).toContain("db.query(`SELECT * FROM users WHERE name = $1 AND age > $2`, [name, age]);");
    expect(count(dir, "sql-injection")).toBe(0);
  });

  it("LIKE patterns keep their wildcards inside the parameter", () => {
    const dir = project({ "app.js": route("`SELECT * FROM t WHERE title LIKE '%${name}%'`") });
    expect(fixedText(dir, "app.js", ["sql-injection"])).toContain("db.query(`SELECT * FROM t WHERE title LIKE $1`, [`%${name}%`]);");
  });

  it("a + chain becomes a plain string", () => {
    const dir = project({ "app.js": route(`"SELECT * FROM t WHERE a = '" + name + "' AND b = " + age`) });
    const text = fixedText(dir, "app.js", ["sql-injection"]);
    expect(text).toContain('db.query("SELECT * FROM t WHERE a = $1 AND b = $2", [name, age]);');
    expect(count(dir, "sql-injection")).toBe(0);
  });

  it("uses ? for mysql / sqlite drivers", () => {
    const dir = project({ "app.js": route("`SELECT * FROM t WHERE a = '${name}' AND b = ${age}`") }, { express: "4", mysql2: "3" });
    expect(fixedText(dir, "app.js", ["sql-injection"])).toContain("db.query(`SELECT * FROM t WHERE a = ? AND b = ?`, [name, age]);");
  });

  it("leaves table names, ORDER BY, joined lists, glued names and existing parameter arrays to a person", () => {
    const cases: Array<[string, RegExp]> = [
      ["`SELECT * FROM ${name} WHERE id = 1`", /table or column name/],
      ["`SELECT * FROM t ORDER BY ${name}`", /table or column name/],
      ["`SELECT * FROM t WHERE id IN (${[name, age].join(',')})`", /joined/],
      ["`SELECT * FROM user_${name}`", /glued|table or column name/],
    ];
    for (const [query, reason] of cases) {
      const dir = project({ "app.js": route(query) });
      const p = plan(dir, ["sql-injection"]);
      expect(p.edits).toHaveLength(0);
      expect(p.skipped.map((s) => s.reason).join(" ")).toMatch(reason);
    }
    const withParams = project({ "app.js": route("`SELECT * FROM t WHERE a = ${name}`, [age]") });
    expect(plan(withParams, ["sql-injection"]).skipped[0]?.reason).toContain("values array");
  });

  it("does not guess the placeholder style when the driver is unknown", () => {
    const dir = project({ "app.js": route("`SELECT * FROM t WHERE a = ${name}`") }, { express: "4" });
    const p = plan(dir, ["sql-injection"]);
    expect(p.edits).toHaveLength(0);
    expect(p.skipped[0]?.reason).toContain("driver was not recognised");
  });
});

describe("fix: JSON Web Tokens", () => {
  const head = `const jwt = require("jsonwebtoken");\n`;

  it("adds an expiry to sign(), whether the options exist or not, and to a jose chain", () => {
    const dir = project({
      "a.js": head + `const t1 = jwt.sign({ id: 1 }, secret);\nconst t2 = jwt.sign({ id: 2 }, secret, { algorithm: "HS256" });\nconst t3 = jwt.sign({ id: 3 }, secret, {});\n`,
      "b.js": `import { SignJWT } from "jose";\nconst t = await new SignJWT({ id: 1 })\n  .setProtectedHeader({ alg: "HS256" })\n  .sign(key);\n`,
    });
    const p = plan(dir, ["insecure-jwt"]);
    applyPlan(p);
    expect(read(dir, "a.js")).toContain('jwt.sign({ id: 1 }, secret, { expiresIn: "1h" })');
    expect(read(dir, "a.js")).toContain('{ expiresIn: "1h", algorithm: "HS256" }');
    expect(read(dir, "a.js")).toContain('{ expiresIn: "1h" }');
    expect(read(dir, "b.js")).toContain('.setProtectedHeader({ alg: "HS256" })\n  .setExpirationTime("1h").sign(key)');
    expect(count(dir, "insecure-jwt")).toBe(0);
    expect(p.todo.join(" ")).toContain("expire after 1 hour");
  });

  it("removes the none algorithm and ignoreExpiration, wherever they sit in the list", () => {
    const dir = project({
      "a.js":
        head +
        `jwt.verify(t, s, { algorithms: ["none", "HS256"] });\n` +
        `jwt.verify(t, s, { algorithms: ["HS256", "none"] });\n` +
        `jwt.verify(t, s, { algorithms: ["none"] });\n` +
        `jwt.verify(t, s, { ignoreExpiration: true, algorithms: ["HS256"] });\n` +
        `jwt.verify(t, s, { algorithms: ["HS256"], ignoreExpiration: true });\n` +
        `jwt.sign({ id: 1 }, s, { algorithm: "none", expiresIn: "1h" });\n`,
    });
    const text = fixedText(dir, "a.js", ["insecure-jwt"]);
    expect(text).toContain('{ algorithms: ["HS256"] });\njwt.verify(t, s, { algorithms: ["HS256"] });\njwt.verify(t, s, { algorithms: ["HS256"] });');
    expect(text).toContain('{ algorithm: "HS256", expiresIn: "1h" }');
    expect(text).not.toMatch(/none|ignoreExpiration/);
    expect(count(dir, "insecure-jwt")).toBe(0);
  });

  it("does not turn jwt.decode into verify by itself", () => {
    const dir = project({ "a.js": head + `app.get("/p", (req, res) => { const c = jwt.decode(req.headers.authorization); res.send(c.role); });\n` });
    const p = plan(dir, ["insecure-jwt"]);
    expect(p.edits).toHaveLength(0);
    expect(p.skipped[0]?.reason).toContain("jwt.verify");
  });
});

describe("fix: secrets move to .env", () => {
  const KEY = "sup3r-s3cret-v4lue-9f2a1c7e5b";

  it("names the variable after what it holds and keeps the value out of every preview", () => {
    const dir = project({
      "config.js": `module.exports = { apiKey: "${KEY}-a", dbPassword: "${KEY}-b" };\nconst jwtSecret = "${KEY}-c";\n`,
      "server.js": `const jwt = require("jsonwebtoken");\napp.use(session({ secret: "${KEY}-d" }));\njwt.sign({ id: 1 }, "${KEY}-e", { expiresIn: "1h" });\n`,
    });
    const p = plan(dir, ["hardcoded-secret"]);
    const preview = renderPlan(p, dir);
    expect(preview).not.toContain(KEY);
    expect(preview).toContain("<hidden>");
    expect(preview).toContain("<the value moved out of your source code>");
    applyPlan(p);
    expect(read(dir, "config.js")).toContain("apiKey: process.env.API_KEY, dbPassword: process.env.DB_PASSWORD");
    expect(read(dir, "config.js")).toContain("const jwtSecret = process.env.JWT_SECRET;");
    expect(read(dir, "server.js")).toContain("session({ secret: process.env.SESSION_SECRET })");
    expect(read(dir, "server.js")).toContain("jwt.sign({ id: 1 }, process.env.JWT_SECRET_2");
    const env = read(dir, ".env");
    expect(env).toContain(`API_KEY=${KEY}-a`);
    expect(env).toContain(`SESSION_SECRET=${KEY}-d`);
    expect(read(dir, ".env.example")).toMatch(/^API_KEY=$/m);
    expect(read(dir, ".env.example")).not.toContain(KEY);
    expect(read(dir, ".gitignore")).toMatch(/^\.env$/m);
    expect(p.todo[0]).toMatch(/^ROTATE 5 secret/);
  });

  it("drops a hard-coded fallback next to process.env, and adds ! in TypeScript", () => {
    const dir = project({
      "a.js": `const apiKey = process.env.NEWS_KEY || "${KEY}-f";\n`,
      "b.ts": `export const token: string = "${KEY}-g";\n`,
    });
    applyPlan(plan(dir, ["hardcoded-secret"]));
    expect(read(dir, "a.js")).toContain("const apiKey = process.env.NEWS_KEY;");
    expect(read(dir, "b.ts")).toContain("export const token: string = process.env.TOKEN!;");
    expect(count(dir, "hardcoded-secret")).toBe(0);
  });

  it("appends to an existing .env.example and .gitignore instead of replacing them, and never overwrites a variable", () => {
    const dir = project({
      "config.js": `const apiKey = "${KEY}-h";\n`,
      ".env.example": "PORT=3000",
      ".gitignore": "node_modules\n",
      ".env": "API_KEY=already-here\n",
    });
    applyPlan(plan(dir, ["hardcoded-secret"]));
    expect(read(dir, ".env.example")).toBe("PORT=3000\nAPI_KEY=\n");
    expect(read(dir, ".gitignore")).toBe("node_modules\n.env\n");
    expect(read(dir, ".env")).toBe("API_KEY=already-here\n");
  });

  it("leaves browser files and NEXT_PUBLIC_ variables to a person", () => {
    const dir = project({
      "client.js": `"use client";\nconst apiKey = "${KEY}-i";\n`,
      "pub.js": `const x = process.env.NEXT_PUBLIC_API_SECRET;\n`,
    });
    const p = plan(dir, ["hardcoded-secret"]);
    expect(p.edits).toHaveLength(0);
    expect(p.skipped.map((s) => s.reason).join(" ")).toMatch(/runs in the browser/);
    expect(p.skipped.map((s) => s.reason).join(" ")).toMatch(/public prefix/);
  });
});

describe("fix: Supabase and CORS", () => {
  it("writes one migration that enables RLS for every open table, next to the existing migrations", () => {
    const dir = project({
      "supabase/migrations/001_init.sql": "create table public.todos (id int primary key, user_id uuid);\ncreate table public.notes (id int primary key);\n",
    }, { next: "15", "@supabase/supabase-js": "2" });
    const p = plan(dir, ["supabase-rls"]);
    expect(p.writes).toHaveLength(1);
    const write = p.writes[0]!;
    expect(path.dirname(write.file)).toBe(path.join(dir, "supabase", "migrations"));
    expect(path.basename(write.file)).toMatch(/^\d{14}_enable_row_level_security\.sql$/);
    expect(write.content).toContain("ALTER TABLE public.todos ENABLE ROW LEVEL SECURITY;");
    expect(write.content).toContain("ALTER TABLE public.notes ENABLE ROW LEVEL SECURITY;");
    expect(write.content).toContain("-- CREATE POLICY");
    expect(p.todo.join(" ")).toContain("write the policies");
    applyPlan(p);
    expect(count(dir, "supabase-rls")).toBe(0);
  });

  it("puts the migration in supabase/migrations even when the table is defined in supabase/schema.sql", () => {
    const dir = project({ "supabase/schema.sql": "create table public.items (id int primary key);\n" }, { next: "15", "@supabase/supabase-js": "2" });
    const write = plan(dir, ["supabase-rls"]).writes[0]!;
    expect(path.dirname(write.file)).toBe(path.join(dir, "supabase", "migrations"));
  });

  it("CORS: the allowed origins come from ALLOWED_ORIGINS", () => {
    const dir = project({ "app.js": `const cors = require("cors");\napp.use(cors({ origin: true, credentials: true }));\n` });
    const p = plan(dir, ["insecure-cors"]);
    applyPlan(p);
    expect(read(dir, "app.js")).toContain('origin: (process.env.ALLOWED_ORIGINS ?? "").split(",").filter(Boolean)');
    expect(read(dir, ".env.example")).toMatch(/^ALLOWED_ORIGINS=$/m);
    expect(p.todo.join(" ")).toContain("ALLOWED_ORIGINS");
    expect(count(dir, "insecure-cors")).toBe(0);
  });
});

describe("fix: plan and apply", () => {
  it("a plan changes nothing until it is applied, and --only limits it", () => {
    const dir = project({ "a.js": route("`SELECT * FROM t WHERE a = ${name}`") + `const jwt = require("jsonwebtoken");\njwt.sign({ id: 1 }, secret);\n` });
    const before = read(dir, "a.js");
    const all = plan(dir);
    expect(all.edits.length).toBeGreaterThanOrEqual(2);
    expect(read(dir, "a.js")).toBe(before);
    expect(plan(dir, ["insecure-jwt"]).edits).toHaveLength(1);
  });

  it("makes .security-hub.bak copies when asked, and the preview is a real unified diff", () => {
    const dir = project({ "a.js": route("`SELECT * FROM t WHERE a = ${name}`") });
    const p = plan(dir, ["sql-injection"]);
    const diff = renderPlan(p, dir);
    expect(diff).toMatch(/^--- a\/a\.js\n\+\+\+ b\/a\.js\n@@ -\d+,\d+ \+\d+,\d+ @@/);
    expect(diff).toContain("-  db.query(`SELECT * FROM t WHERE a = ${name}`);");
    expect(diff).toContain("+  db.query(`SELECT * FROM t WHERE a = $1`, [name]);");
    const original = read(dir, "a.js");
    const result = applyPlan(p, { backup: true });
    expect(result.backups).toEqual([path.join(dir, "a.js.security-hub.bak")]);
    expect(fs.readFileSync(result.backups[0]!, "utf8")).toBe(original);
  });

  it("a project with nothing fixable gives an empty plan", () => {
    const dir = project({ "a.js": `const x = 1;\n` });
    const p = plan(dir);
    expect(p.edits).toHaveLength(0);
    expect(p.writes).toHaveLength(0);
  });
});

describe("fix: Sequelize, promise chains and browser projects", () => {
  it("Sequelize takes { replacements: [...] } with ? placeholders, and the chain after query() is kept", () => {
    const dir = project(
      { "app.js": `app.get("/s", (req, res) => {\n  models.sequelize.query(\`SELECT * FROM p WHERE n LIKE '%\${req.query.q}%'\`).then((r) => res.json(r)).catch(() => res.end());\n});\n` },
      { express: "4", sequelize: "6", sqlite3: "5" },
    );
    const text = fixedText(dir, "app.js", ["sql-injection"]);
    expect(text).toContain("models.sequelize.query(`SELECT * FROM p WHERE n LIKE ?`, { replacements: [`%${req.query.q}%`] }).then(");
    expect(count(dir, "sql-injection")).toBe(0);
  });

  it("a secret in a browser app is left alone: an environment variable would be public there too", () => {
    const dir = project({ "src/api.ts": `export const apiKey = "sup3r-s3cret-v4lue-9f2a1c7e5b";\n` }, { "@angular/core": "17" });
    const p = plan(dir, ["hardcoded-secret"]);
    expect(p.edits).toHaveLength(0);
    expect(p.skipped[0]?.reason).toContain("browser app");
  });

  it("a hard-coded fallback in TypeScript keeps the type a string", () => {
    const dir = project({ "a.ts": `const apiKey: string = process.env.NEWS_KEY || "sup3r-s3cret-v4lue-9f2a1c7e5b";\n` });
    expect(fixedText(dir, "a.ts", ["hardcoded-secret"])).toContain("const apiKey: string = process.env.NEWS_KEY!;");
  });
});
