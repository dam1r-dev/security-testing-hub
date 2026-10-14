import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { defaultAnalyzers, scanPath, scanSource } from "../src/index";

// insecure-cors, insecure-jwt, missing-rate-limit, exposed-files

const dirs: string[] = [];
afterAll(() => dirs.forEach((d) => fs.rmSync(d, { recursive: true, force: true })));

function project(files: Record<string, string>, dependencies: Record<string, string> = { express: "4" }): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "sh-newrules-"));
  dirs.push(dir);
  fs.writeFileSync(path.join(dir, "package.json"), JSON.stringify({ dependencies }));
  for (const [name, content] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(dir, name)), { recursive: true });
    fs.writeFileSync(path.join(dir, name), content);
  }
  return dir;
}
const found = (dir: string, ruleId: string) => scanPath(dir).results.flatMap((r) => r.findings).filter((f) => f.ruleId === ruleId);
const inline = (code: string, ruleId: string, file = "app.js") => scanSource(code, file, defaultAnalyzers()).findings.filter((f) => f.ruleId === ruleId);

describe("insecure-cors", () => {
  it("origin: true (or an allow-everything callback, or a catch-all regex) together with credentials", () => {
    expect(inline(`app.use(cors({ origin: true, credentials: true }));`, "insecure-cors")).toHaveLength(1);
    expect(inline(`app.use(cors({ origin: (origin, cb) => cb(null, true), credentials: true }));`, "insecure-cors")).toHaveLength(1);
    expect(inline(`app.use(cors({ origin: /.*/, credentials: true }));`, "insecure-cors")).toHaveLength(1);
    expect(inline(`await app.register(cors, { origin: true, credentials: true });`, "insecure-cors")).toHaveLength(1);
    const [finding] = inline(`app.use(cors({ origin: true, credentials: true }));`, "insecure-cors");
    expect(finding).toMatchObject({ severity: "high", confidence: "high" });
  });

  it("a named origin, a list, an allowlist callback, a wildcard, or no credentials is fine", () => {
    expect(inline(`app.use(cors({ origin: "https://app.example.com", credentials: true }));`, "insecure-cors")).toHaveLength(0);
    expect(inline(`app.use(cors({ origin: ["https://a.example.com"], credentials: true }));`, "insecure-cors")).toHaveLength(0);
    expect(inline(`app.use(cors({ origin: (o, cb) => cb(null, ALLOWED.includes(o)), credentials: true }));`, "insecure-cors")).toHaveLength(0);
    expect(inline(`app.use(cors({ origin: "*", credentials: true }));`, "insecure-cors")).toHaveLength(0);
    expect(inline(`app.use(cors({ origin: true }));`, "insecure-cors")).toHaveLength(0);
    expect(inline(`app.use(cors());`, "insecure-cors")).toHaveLength(0);
  });

  it("a reflected Origin header with credentials, written by hand", () => {
    const express = `app.use((req, res, next) => {\n  res.setHeader("Access-Control-Allow-Origin", req.headers.origin);\n  res.setHeader("Access-Control-Allow-Credentials", "true");\n  next();\n});`;
    expect(inline(express, "insecure-cors")).toHaveLength(1);
    const next = `export async function GET(request: Request) {\n  const origin = request.headers.get("origin");\n  return new Response("x", { headers: { "Access-Control-Allow-Origin": request.headers.get("origin")!, "Access-Control-Allow-Credentials": "true" } });\n}`;
    expect(inline(next, "insecure-cors", "route.ts")).toHaveLength(1);
    expect(inline(`res.setHeader("Access-Control-Allow-Origin", req.headers.origin);`, "insecure-cors")).toHaveLength(0);
    expect(inline(`res.setHeader("Access-Control-Allow-Origin", "*");\nres.setHeader("Access-Control-Allow-Credentials", "true");`, "insecure-cors")).toHaveLength(0);
  });
});

describe("insecure-jwt", () => {
  const head = `const jwt = require("jsonwebtoken");\n`;

  it("accepts unsigned tokens, ignores expiry, issues unsigned tokens", () => {
    const [none] = inline(head + `jwt.verify(t, secret, { algorithms: ["HS256", "none"] });`, "insecure-jwt");
    expect(none).toMatchObject({ severity: "critical", confidence: "high" });
    expect(inline(head + `jwt.verify(t, secret, { ignoreExpiration: true });`, "insecure-jwt")[0]).toMatchObject({ severity: "high" });
    expect(inline(head + `jwt.sign({ id: 1 }, secret, { algorithm: "none" });`, "insecure-jwt")[0]).toMatchObject({ severity: "critical" });
    expect(inline(head + `jwt.verify(t, secret, { algorithms: ["HS256"] });`, "insecure-jwt")).toHaveLength(0);
  });

  it("tokens that never expire, only when the payload and options are written out", () => {
    expect(inline(head + `const t = jwt.sign({ id: user.id }, process.env.JWT_SECRET);`, "insecure-jwt")).toHaveLength(1);
    expect(inline(head + `const t = jwt.sign({ id: user.id }, secret, { algorithm: "HS256" });`, "insecure-jwt")).toHaveLength(1);
    expect(inline(head + `const t = jwt.sign({ id: user.id }, secret, { expiresIn: "1h" });`, "insecure-jwt")).toHaveLength(0);
    expect(inline(head + `const t = jwt.sign({ id: user.id, exp: now + 3600 }, secret);`, "insecure-jwt")).toHaveLength(0);
    expect(inline(head + `const t = jwt.sign(payload, secret);`, "insecure-jwt")).toHaveLength(0); // payload unknown
    expect(inline(head + `const t = jwt.sign({ ...base, id: 1 }, secret);`, "insecure-jwt")).toHaveLength(0);
    expect(inline(head + `const t = jwt.sign({ id: 1 }, secret, options);`, "insecure-jwt")).toHaveLength(0);
  });

  it("recognises aliases and named imports", () => {
    expect(inline(`import { sign } from "jsonwebtoken";\nconst t = sign({ id: 1 }, secret);`, "insecure-jwt")).toHaveLength(1);
    expect(inline(`import jsonwebtoken from "jsonwebtoken";\nconst t = jsonwebtoken.sign({ id: 1 }, secret);`, "insecure-jwt")).toHaveLength(1);
    expect(inline(`const { verify } = require("jsonwebtoken");\nverify(t, s, { ignoreExpiration: true });`, "insecure-jwt")).toHaveLength(1);
    expect(inline(`const t = jwt.sign({ id: 1 }, secret);`, "insecure-jwt")).toHaveLength(0); // no jsonwebtoken in this file
  });

  it("decode used on a token the client sent, in a file that never verifies", () => {
    expect(inline(head + `app.get("/p", (req, res) => { const c = jwt.decode(req.headers.authorization); res.send(c.role); });`, "insecure-jwt")).toHaveLength(1);
    expect(inline(head + `function who(token) { return jwt.decode(token).id; }`, "insecure-jwt")).toHaveLength(1);
    // the token is one the server holds: nothing to forge
    expect(inline(head + `const stored = tokens.get(userId); const c = jwt.decode(stored);`, "insecure-jwt")).toHaveLength(0);
    // the file verifies too
    expect(inline(head + `app.get("/p", (req, res) => { jwt.verify(req.headers.authorization, s); const c = jwt.decode(req.headers.authorization); });`, "insecure-jwt")).toHaveLength(0);
  });

  it("jose: SignJWT without setExpirationTime", () => {
    const jose = `import { SignJWT } from "jose";\n`;
    expect(inline(jose + `const t = await new SignJWT({ id: 1 }).setProtectedHeader({ alg: "HS256" }).sign(key);`, "insecure-jwt")).toHaveLength(1);
    expect(inline(jose + `const t = await new SignJWT({ id: 1 }).setProtectedHeader({ alg: "HS256" }).setExpirationTime("2h").sign(key);`, "insecure-jwt")).toHaveLength(0);
  });

  it("client components are not server code", () => {
    expect(inline(`"use client";\n` + head + `const t = jwt.sign({ id: 1 }, secret);`, "insecure-jwt")).toHaveLength(0);
  });
});

describe("missing-rate-limit", () => {
  const login = `const bcrypt = require("bcrypt");\nmodule.exports = (app, db) => {\n  app.post("/login", async (req, res) => {\n    const user = await db.findUser(req.body.email);\n    const ok = await bcrypt.compare(req.body.password, user.hash);\n    res.send({ ok });\n  });\n};\n`;

  it("reports a login route that checks the password itself, in a project with no limiter", () => {
    const [finding] = found(project({ "routes.js": login }), "missing-rate-limit");
    expect(finding).toMatchObject({ severity: "medium", confidence: "medium" });
    expect(finding?.message).toContain("POST /login");
    expect(finding?.message).toContain("security-hub-ignore missing-rate-limit");
  });

  it("is quiet when a limiter package is installed, or any source mentions rate limiting", () => {
    expect(found(project({ "routes.js": login }, { express: "4", "express-rate-limit": "7" }), "missing-rate-limit")).toHaveLength(0);
    expect(found(project({ "routes.js": login, "limits.js": `const limiter = createLimiter({ windowMs: 60000, max: 5 });\n` }), "missing-rate-limit")).toHaveLength(0);
    expect(found(project({ "routes.js": login, "guard.js": `if (attempts > 5) return res.status(429).end();\n` }), "missing-rate-limit")).toHaveLength(0);
  });

  it("is quiet for hosted sign-in and for routes that check nothing themselves", () => {
    expect(found(project({ "routes.js": `module.exports = (app) => app.post("/login", async (req, res) => { const { data } = await supabase.auth.signInWithPassword(req.body); res.send(data); });\n` }), "missing-rate-limit")).toHaveLength(0);
    expect(found(project({ "routes.js": `module.exports = (app) => app.post("/login", (req, res) => res.redirect("/"));\n` }), "missing-rate-limit")).toHaveLength(0);
    expect(found(project({ "routes.js": `const bcrypt = require("bcrypt");\nmodule.exports = (app) => app.post("/profile", async (req, res) => { await bcrypt.compare(a, b); res.end(); });\n` }), "missing-rate-limit")).toHaveLength(0);
  });

  it("follows the handler into a controller file", () => {
    const dir = project({
      "routes.js": `const ctl = require("./controller");\nmodule.exports = (app) => app.post("/auth/login", ctl.login);\n`,
      "controller.js": `const bcrypt = require("bcrypt");\nexports.login = async (req, res) => { const ok = await bcrypt.compare(req.body.password, "h"); res.send({ ok }); };\n`,
    });
    expect(found(dir, "missing-rate-limit")).toHaveLength(1);
  });

  it("covers Next route handlers, Server Actions and the Auth.js Credentials provider", () => {
    const next = project({ "app/api/login/route.ts": `import bcrypt from "bcrypt";\nexport async function POST(request: Request) { const { password } = await request.json(); const ok = await bcrypt.compare(password, "h"); return Response.json({ ok }); }\n` }, { next: "15" });
    expect(found(next, "missing-rate-limit")).toHaveLength(1);
    const action = project({ "app/actions.ts": `"use server";\nimport bcrypt from "bcrypt";\nexport async function login(formData: FormData) { const ok = await bcrypt.compare(String(formData.get("p")), "h"); return ok; }\n` }, { next: "15" });
    expect(found(action, "missing-rate-limit")).toHaveLength(1);
    const authjs = project({ "auth.ts": `import Credentials from "next-auth/providers/credentials";\nimport bcrypt from "bcrypt";\nexport const providers = [Credentials({ async authorize(c) { return (await bcrypt.compare(c.password, "h")) ? { id: 1 } : null; } })];\n` }, { next: "15", "next-auth": "5" });
    expect(found(authjs, "missing-rate-limit")).toHaveLength(1);
  });

  it("one finding per file, however many endpoints", () => {
    const twice = `const bcrypt = require("bcrypt");\nmodule.exports = (app) => {\n  app.post("/login", async (req, res) => { await bcrypt.compare(a, b); });\n  app.post("/admin/login", async (req, res) => { await bcrypt.compare(a, b); });\n};\n`;
    const result = found(project({ "routes.js": twice }), "missing-rate-limit");
    expect(result).toHaveLength(1);
    expect(result[0]?.message).toContain("2 sign-in");
  });
});

describe("exposed-files", () => {
  const SECRET_ENV = "SESSION_SECRET=correct-horse-battery-staple\nADMIN_PASSWORD=changeme-please\n";
  const names = (dir: string) => found(dir, "exposed-files").map((f) => path.relative(dir, f.location.file).split(path.sep).join("/")).sort();

  it("an .env, a dump, a database file and a .git folder inside public/", () => {
    const dir = project({
      "public/.env": SECRET_ENV,
      "public/backup.sql": "INSERT INTO users VALUES (1);\n",
      "public/data.sqlite": "SQLite format 3\0",
      "public/.git/config": "[core]\n",
      "public/logo.png": "png",
      "public/robots.txt": "User-agent: *\n",
    }, { next: "15" });
    expect(names(dir)).toEqual(["public/.env", "public/.git", "public/backup.sql", "public/data.sqlite"]);
    const env = found(dir, "exposed-files").find((f) => f.location.file.endsWith(".env"));
    expect(env).toMatchObject({ severity: "critical", confidence: "high" });
    expect(env?.message).toContain("/.env");
    expect(env?.message).not.toContain("correct-horse");
  });

  it("private keys and service-account files, by content", () => {
    const header = "-----BEGIN " + "PRIVATE KEY-----";
    const dir = project({
      "public/server.pem": `${header}\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n`,
      "public/cert.pem": "-----BEGIN CERTIFICATE-----\nMIIC\n",
      "public/serviceAccount.json": JSON.stringify({ type: "service_account", private_key: "x" }),
      "public/credentials.json": JSON.stringify({ note: "nothing here" }),
    }, { next: "15" });
    expect(names(dir)).toEqual(["public/server.pem", "public/serviceAccount.json"]);
  });

  it("templates and empty files are fine", () => {
    const dir = project({ "public/.env.example": SECRET_ENV, "public/.env.sample": SECRET_ENV, "public/.env.local": "" }, { next: "15" });
    expect(names(dir)).toEqual([]);
  });

  it("static/ and www/ folders count too, and node_modules does not", () => {
    const dir = project({ "static/dump.sql": "x\n", "www/site-backup.zip": "zip", "node_modules/pkg/public/leak.sql": "x\n" });
    expect(names(dir)).toEqual(["static/dump.sql", "www/site-backup.zip"]);
  });

  it("express.static on the project folder serves everything; a dedicated folder is checked for what is in it", () => {
    const root = project({ "app.js": `const express = require("express");\nconst app = express();\napp.use(express.static(__dirname));\n` });
    const [rootFinding] = found(root, "exposed-files");
    expect(rootFinding).toMatchObject({ severity: "critical", confidence: "high" });
    expect(rootFinding?.message).toContain("whole project folder");

    const dedicated = project({
      "src/server.js": `const express = require("express");\nconst path = require("path");\nconst app = express();\napp.use(express.static(path.join(__dirname, "..", "files")));\n`,
      "files/db.sqlite": "SQLite format 3\0",
    });
    expect(names(dedicated)).toEqual(["files/db.sqlite"]);

    const safe = project({ "app.js": `app.use(express.static(path.join(__dirname, "public")));\n`, "public/index.html": "<html></html>" });
    expect(names(safe)).toEqual([]);
  });

  it("can be silenced with .security-hub-ignore", () => {
    const dir = project({ "public/backup.sql": "x\n", ".security-hub-ignore": "public/backup.sql\n" }, { next: "15" });
    expect(names(dir)).toEqual([]);
  });
});

describe("exposed-files: found by scanning this project with itself", () => {
  it("the words express.static('.') in a message, a comment or documentation are not a call", () => {
    const dir = project({
      "docs.js": `// do not write express.static(".") or express.static(__dirname)\nconst advice = 'never call express.static(".")';\nconst other = "serveStatic(__dirname)";\n`,
    });
    expect(found(dir, "exposed-files")).toHaveLength(0);
  });

  it("a source file named after secrets is code, not a file of credentials", () => {
    const dir = project(
      { "public/secrets.ts": `export const note = "the password and the secret live in the vault";\n`, "public/credentials.json": JSON.stringify({ password: "x" }) },
      { next: "15" },
    );
    const names = found(dir, "exposed-files").map((f) => path.basename(f.location.file));
    expect(names).toEqual(["credentials.json"]);
  });
});
