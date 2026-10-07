import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { scanPath } from "../src/index";

/** Writes `files` (relative path -> source) into a fresh temp project and scans it. */
function scanProject(files: Record<string, string>) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "sh-cross-"));
  for (const [rel, source] of Object.entries(files)) {
    const full = path.join(dir, rel);
    fs.mkdirSync(path.dirname(full), { recursive: true });
    fs.writeFileSync(full, source);
  }
  const summary = scanPath(dir);
  const findings = summary.results.flatMap((r) =>
    r.findings.map((f) => ({ ...f, file: path.relative(dir, r.file).split(path.sep).join("/") })),
  );
  fs.rmSync(dir, { recursive: true, force: true });
  return findings;
}

const byRule = (findings: ReturnType<typeof scanProject>, rule: string) => findings.filter((f) => f.ruleId === rule);

describe("cross-file taint: CommonJS", () => {
  it("follows req.query into a service function that builds SQL (route -> service)", () => {
    const findings = scanProject({
      "routes/users.js": `
        const userService = require("../services/user-service");
        module.exports = (app) => {
          app.get("/users", (req, res) => {
            res.json(userService.findByName(req.query.name));
          });
        };`,
      "services/user-service.js": `
        const db = require("../db");
        exports.findByName = (name) => db.query("SELECT * FROM users WHERE name = '" + name + "'");`,
    });
    const sqli = byRule(findings, "sql-injection");
    expect(sqli).toHaveLength(1);
    expect(sqli[0]?.file).toBe("routes/users.js");
    expect(sqli[0]?.severity).toBe("critical");
    expect(sqli[0]?.message).toContain("findByName()");
    expect(sqli[0]?.message).toContain("services/user-service.js:3");
  });

  it("handles module.exports = { fn } and destructured require", () => {
    const findings = scanProject({
      "routes.js": `
        const { runReport } = require("./reports");
        app.get("/r", (req, res) => { runReport(req.query.name); res.end(); });`,
      "reports.js": `
        const { exec } = require("child_process");
        function runReport(name) { exec("report --name " + name); }
        module.exports = { runReport };`,
    });
    expect(byRule(findings, "command-injection")).toHaveLength(1);
  });

  it("resolves a module.exports = function and a directory index.js", () => {
    const findings = scanProject({
      "app.js": `
        const search = require("./lib");
        app.get("/s", (req, res) => { search(req.query.q); });`,
      "lib/index.js": `
        module.exports = function search(term) { return db.query(\`SELECT * FROM t WHERE c LIKE '%\${term}%'\`); };`,
    });
    expect(byRule(findings, "sql-injection")).toHaveLength(1);
  });

  it("follows the NodeGoat DAO pattern: constructor function with this.method members", () => {
    const findings = scanProject({
      "routes/files.js": `
        const { FilesDAO } = require("../data/files-dao");
        function FilesHandler(db) {
          const filesDAO = new FilesDAO(db);
          this.show = (req, res) => {
            filesDAO.read(req.query.name);
            res.end();
          };
        }
        module.exports = FilesHandler;`,
      "data/files-dao.js": `
        const fs = require("fs");
        function FilesDAO(db) {
          this.read = (name) => fs.readFileSync("/srv/files/" + name);
        }
        module.exports.FilesDAO = FilesDAO;`,
    });
    const traversal = byRule(findings, "path-traversal");
    expect(traversal).toHaveLength(1);
    expect(traversal[0]?.file).toBe("routes/files.js");
  });

  it("follows prototype methods of a constructor function", () => {
    const findings = scanProject({
      "app.js": `
        const Runner = require("./runner");
        const runner = new Runner();
        app.get("/x", (req, res) => { runner.run(req.query.cmd); });`,
      "runner.js": `
        const cp = require("child_process");
        function Runner() {}
        Runner.prototype.run = function (cmd) { cp.exec(cmd); };
        module.exports = Runner;`,
    });
    expect(byRule(findings, "command-injection")).toHaveLength(1);
  });
});

describe("cross-file taint: ES modules and TypeScript", () => {
  it("follows a Next.js route into a lib function (named import, @/ alias)", () => {
    const findings = scanProject({
      "app/api/user/route.ts": `
        import { getUser } from "@/lib/users";
        export async function GET(request: Request) {
          const id = new URL(request.url).searchParams.get("id");
          return Response.json(await getUser(id));
        }`,
      "lib/users.ts": `
        import { pool } from "./pool";
        export async function getUser(id: string | null) {
          return pool.query(\`SELECT * FROM users WHERE id = \${id}\`);
        }`,
    });
    const sqli = byRule(findings, "sql-injection");
    expect(sqli).toHaveLength(1);
    expect(sqli[0]?.file).toBe("app/api/user/route.ts");
  });

  it("uses tsconfig paths", () => {
    const findings = scanProject({
      "tsconfig.json": `{ "compilerOptions": { "baseUrl": ".", "paths": { "#db/*": ["./src/db/*"] } } /* comment */ }`,
      "src/route.ts": `
        import { find } from "#db/queries";
        export function GET(request: Request) { return find(new URL(request.url).searchParams.get("q")); }`,
      "src/db/queries.ts": `
        export const find = (q: string | null) => db.query("SELECT * FROM t WHERE c = '" + q + "'");`,
    });
    expect(byRule(findings, "sql-injection")).toHaveLength(1);
  });

  it("follows default imports, namespace imports and TS-style .js specifiers", () => {
    const findings = scanProject({
      "a.ts": `
        import svc from "./svc.js";
        import * as util from "./util";
        app.get("/a", (req, res) => { svc.go(req.query.x); util.open(req.query.y); });`,
      "svc.ts": `
        const cp = require("child_process");
        export default { go(x: string) { cp.exec(x); } };`,
      "util.ts": `
        import fs from "fs";
        export function open(p: string) { return fs.readFileSync(p); }`,
    });
    expect(byRule(findings, "command-injection")).toHaveLength(1);
    expect(byRule(findings, "path-traversal")).toHaveLength(1);
  });

  it("follows class instances, this.method() and inheritance", () => {
    const findings = scanProject({
      "routes.ts": `
        import { UserService } from "./user-service";
        const service = new UserService();
        app.get("/u", (req, res) => { service.search(req.query.q); });`,
      "user-service.ts": `
        class BaseService {
          protected run(sql: string) { return db.query(sql); }
        }
        export class UserService extends BaseService {
          search(term: string) { return this.run("SELECT * FROM users WHERE n = '" + term + "'"); }
        }`,
    });
    const sqli = byRule(findings, "sql-injection");
    expect(sqli).toHaveLength(1);
    expect(sqli[0]?.message).toContain("search -> run");
  });

  it("follows barrel files (export * and export { x } from)", () => {
    const findings = scanProject({
      "routes.ts": `
        import { lookup, openFile } from "./services";
        app.get("/a", (req, res) => { lookup(req.query.a); openFile(req.query.b); });`,
      "services/index.ts": `
        export * from "./lookup";
        export { openFile } from "./files";`,
      "services/lookup.ts": `export function lookup(a: string) { return db.query("SELECT " + a); }`,
      "services/files.ts": `
        import fs from "fs";
        export function openFile(p: string) { return fs.readFileSync(p); }`,
    });
    expect(byRule(findings, "sql-injection")).toHaveLength(1);
    expect(byRule(findings, "path-traversal")).toHaveLength(1);
  });
});

describe("cross-function taint: depth and shapes", () => {
  it("follows a three-hop chain controller -> service -> repository", () => {
    const findings = scanProject({
      "controller.js": `
        const service = require("./service");
        app.get("/x", (req, res) => { service.lookup(req.params.id); });`,
      "service.js": `
        const repo = require("./repo");
        exports.lookup = (id) => repo.byId(id);`,
      "repo.js": `
        exports.byId = (id) => db.query("SELECT * FROM t WHERE id = " + id);`,
    });
    const sqli = byRule(findings, "sql-injection");
    expect(sqli).toHaveLength(1);
    expect(sqli[0]?.message).toContain("lookup -> byId");
  });

  it("follows helpers defined in the same file", () => {
    const findings = scanProject({
      "app.js": `
        function find(name) { return db.query("SELECT * FROM u WHERE n = '" + name + "'"); }
        app.get("/u", (req, res) => { res.json(find(req.query.name)); });`,
    });
    expect(byRule(findings, "sql-injection")).toHaveLength(1);
  });

  it("follows a value through a local variable and a destructured request", () => {
    const findings = scanProject({
      "app.js": `
        const { find } = require("./dao");
        app.get("/u", (req, res) => {
          const { name } = req.query;
          const wanted = name;
          find(wanted);
        });`,
      "dao.js": `exports.find = (n) => db.query("SELECT * FROM u WHERE n = '" + n + "'");`,
    });
    expect(byRule(findings, "sql-injection")).toHaveLength(1);
  });

  it("follows a destructured parameter in the callee", () => {
    const findings = scanProject({
      "app.js": `
        const dao = require("./dao");
        app.post("/u", (req, res) => { dao.create(req.body); });`,
      "dao.js": `exports.create = ({ name }) => db.query("INSERT INTO u VALUES ('" + name + "')");`,
    });
    expect(byRule(findings, "sql-injection")).toHaveLength(1);
  });

  it("reports each call once even when several rules and scopes see it", () => {
    const findings = scanProject({
      "app.js": `
        const svc = require("./svc");
        app.get("/x", (req, res) => { svc.go(req.query.v); });`,
      "svc.js": `
        const cp = require("child_process");
        exports.go = (v) => cp.exec("run " + v);`,
    });
    expect(byRule(findings, "command-injection")).toHaveLength(1);
  });

  it("survives mutually recursive functions", () => {
    const findings = scanProject({
      "app.js": `
        function a(x) { return b(x); }
        function b(x) { return a(x); }
        app.get("/x", (req, res) => { a(req.query.v); });`,
    });
    expect(findings).toHaveLength(0);
  });

  it("reaches other rules: open redirect and code injection", () => {
    const findings = scanProject({
      "app.js": `
        const nav = require("./nav");
        app.get("/go", (req, res) => { nav.send(res, req.query.to); });
        app.get("/calc", (req, res) => { nav.calc(req.query.expr); });`,
      "nav.js": `
        exports.send = (res, to) => res.redirect(to);
        exports.calc = (expr) => eval(expr);`,
    });
    expect(byRule(findings, "open-redirect")).toHaveLength(1);
    expect(byRule(findings, "code-injection")).toHaveLength(1);
  });
});

describe("cross-file taint: must stay quiet", () => {
  it("ignores a wrapper that passes user data only as bound parameters", () => {
    const findings = scanProject({
      "app.js": `
        const { query } = require("./db");
        app.get("/u/:id", (req, res) => { query("SELECT * FROM u WHERE id = ?", [req.params.id]); });`,
      "db.js": `
        const pool = require("./pool");
        exports.query = (sql, params) => pool.query(sql, params);`,
    });
    expect(byRule(findings, "sql-injection")).toHaveLength(0);
  });

  it("still flags that same wrapper when user data is concatenated into the SQL text", () => {
    const findings = scanProject({
      "app.js": `
        const { query } = require("./db");
        app.get("/u/:id", (req, res) => { query("SELECT * FROM u WHERE id = " + req.params.id); });`,
      "db.js": `
        const pool = require("./pool");
        exports.query = (sql, params) => pool.query(sql, params);`,
    });
    expect(byRule(findings, "sql-injection")).toHaveLength(1);
  });

  it("ignores values converted to numbers (in the caller or the callee)", () => {
    const findings = scanProject({
      "app.js": `
        const dao = require("./dao");
        app.get("/a", (req, res) => { dao.byId(parseInt(req.query.id, 10)); });
        app.get("/b", (req, res) => { dao.byIdSafe(req.query.id); });`,
      "dao.js": `
        exports.byId = (id) => db.query("SELECT * FROM t WHERE id = " + id);
        exports.byIdSafe = (id) => { const n = parseInt(id, 10); return db.query("SELECT * FROM t WHERE id = " + n); };`,
    });
    expect(byRule(findings, "sql-injection")).toHaveLength(0);
  });

  it("ignores a parameter that never reaches a sink, and the wrong argument position", () => {
    const findings = scanProject({
      "app.js": `
        const svc = require("./svc");
        app.get("/a", (req, res) => { svc.log(req.query.msg); svc.run("ls", req.query.note); });`,
      "svc.js": `
        const cp = require("child_process");
        exports.log = (msg) => console.log(msg);
        exports.run = (cmd, note) => { console.log(note); cp.exec(cmd); };`,
    });
    expect(byRule(findings, "command-injection")).toHaveLength(0);
  });

  it("ignores calls it cannot resolve (npm packages, unknown objects, dynamic requires)", () => {
    const findings = scanProject({
      "app.js": `
        const lodash = require("lodash");
        const mystery = require(process.env.MODULE);
        app.get("/a", (req, res) => { lodash.get(req.query.x); mystery.run(req.query.y); unknown.thing(req.query.z); });`,
    });
    expect(findings).toHaveLength(0);
  });

  it("does not follow a parameter that shadows an outer function of the same name", () => {
    const findings = scanProject({
      "app.js": `
        function find(name) { return db.query("SELECT " + name); }
        function handler(find) { find(req.query.x); }
        app.get("/a", (req, res) => handler(() => 1));`,
    });
    expect(byRule(findings, "sql-injection")).toHaveLength(0);
  });

  it("does not treat a value looked up by a user-chosen KEY as user-controlled (hackathon-starter token revocation)", () => {
    const findings = scanProject({
      "controller.js": `
        const { revokeProviderTokens } = require("./revocation");
        app.post("/unlink/:provider", async (req, res) => { await revokeProviderTokens(req.params.provider, "t"); });`,
      "revocation.js": `
        const CONFIG = { github: { revokeURL: "https://api.github.com/revoke" } };
        async function revokeToken(url, token) { const finalURL = url + "?t=" + token; return fetch(finalURL); }
        async function revokeProviderTokens(providerName, tokenData) {
          const config = CONFIG[providerName];
          if (!config) return;
          await revokeToken(config.revokeURL, tokenData);
        }
        exports.revokeProviderTokens = revokeProviderTokens;`,
    });
    expect(byRule(findings, "ssrf")).toHaveLength(0);
  });

  it("applies the same rule inside one function: table[userKey] is not tainted", () => {
    const findings = scanProject({
      "app.js": `
        const HOSTS = { a: "https://a.example", b: "https://b.example" };
        app.get("/x", async (req, res) => {
          const target = HOSTS[req.query.which];
          res.json(await fetch(target));
        });`,
    });
    expect(byRule(findings, "ssrf")).toHaveLength(0);
  });

  it("does not treat the real DB wrapper as a helper to inspect twice", () => {
    // db.query is already a direct sink: one finding, not two.
    const findings = scanProject({
      "app.js": `
        const db = require("./db");
        app.get("/u", (req, res) => { db.query("SELECT * FROM u WHERE n = '" + req.query.n + "'"); });`,
      "db.js": `exports.query = (sql) => pool.query(sql);`,
    });
    expect(byRule(findings, "sql-injection")).toHaveLength(1);
  });
});

describe("destructuring and shorthand in the same function", () => {
  it("taints names bound by `const { id } = req.params`", () => {
    const findings = scanProject({
      "app.js": `
        app.get("/u/:id", (req, res) => {
          const { id } = req.params;
          db.query(\`SELECT * FROM u WHERE id = \${id}\`);
        });`,
    });
    expect(byRule(findings, "sql-injection")).toHaveLength(1);
  });

  it("sees a shorthand property in a Mongo query as a use of the variable", () => {
    const findings = scanProject({
      "app.js": `
        app.post("/login", async (req, res) => {
          const username = req.body.username;
          await User.findOne({ username });
        });`,
    });
    expect(byRule(findings, "nosql-injection")).toHaveLength(1);
  });
});

describe("res.send with an object literal", () => {
  it("is a JSON response, not reflected XSS", () => {
    const findings = scanProject({
      "app.js": `
        app.post("/t", (req, res) => {
          const { amount, to } = req.body;
          res.send({ status: "ok", amount, to });
        });
        app.get("/u", (req, res) => { res.send([req.query.a]); });`,
    });
    expect(byRule(findings, "xss")).toHaveLength(0);
  });

  it("still flags a string or template response built from request data", () => {
    const findings = scanProject({
      "app.js": `
        app.get("/h", (req, res) => { const { name } = req.query; res.send(\`<h1>Hello \${name}</h1>\`); });`,
    });
    expect(byRule(findings, "xss")).toHaveLength(1);
  });
});
