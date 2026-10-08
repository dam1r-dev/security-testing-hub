import { scanSource } from "../src/index";
import { CsrfAnalyzer } from "../src/analyzers/csrf";
import { IdorAnalyzer } from "../src/analyzers/idor";
import { HardcodedSecretAnalyzer } from "../src/analyzers/hardcoded-secret";
import { UsernameEnumerationAnalyzer } from "../src/analyzers/username-enumeration";
import { OpenRedirectAnalyzer } from "../src/analyzers/open-redirect";
import { PathTraversalAnalyzer } from "../src/analyzers/path-traversal";
import { SqlInjectionAnalyzer } from "../src/analyzers/sql-injection";
import { CommandInjectionAnalyzer } from "../src/analyzers/command-injection";
import { XxeAnalyzer } from "../src/analyzers/xxe";
import { NoSqlInjectionAnalyzer } from "../src/analyzers/nosql-injection";
import { cookieProjectFile, projectFile } from "./helpers/cookie-project";

// Regression cases from the validation round on nine more real projects (docs/validation.md, Round 6):
// each one is a false positive (or a miss) that the first pass produced on real code.

const n = (source: string, file: string, analyzer: Parameters<typeof scanSource>[2]) => scanSource(source, file, analyzer).findings.length;

describe("CSRF only applies where a browser attaches the credential by itself", () => {
  const a = [new CsrfAnalyzer()];
  const route = `export async function POST(request) { const body = await request.json(); return Response.json(body); }`;

  it("skips projects whose session cookie is SameSite=Lax by default (Auth.js, Clerk, Supabase SSR)", () => {
    for (const dep of ["next-auth", "@clerk/nextjs", "@supabase/ssr", "better-auth"]) {
      expect(n(route, projectFile({ [dep]: "1" }, "app/api/x/route.ts"), a)).toBe(0);
    }
  });

  it("skips a project with no authentication library at all (a demo / public API)", () => {
    expect(n(`router.post("/post", handler);`, projectFile({ express: "4", "@prisma/client": "5" }, "src/index.js"), a)).toBe(0);
  });

  it("still flags cookie/session middleware that the app configures itself", () => {
    expect(n(`router.post("/post", handler);`, projectFile({ express: "4", "express-session": "1" }, "src/index.js"), a)).toBe(1);
    expect(n(`router.post("/post", handler);`, projectFile({ express: "4", "cookie-parser": "1" }, "src/index.js"), a)).toBe(1);
  });

  it("skips a route that a deny-everything middleware switches off, and on-demand revalidation endpoints", () => {
    expect(n(`app.post("/api/Products", security.denyAll());`, cookieProjectFile("server.js"), a)).toBe(0);
    expect(n(route, cookieProjectFile("app/api/revalidate/route.ts"), a)).toBe(0);
  });
});

describe("IDOR needs per-user data and a handler that can read the id", () => {
  const a = [new IdorAnalyzer()];

  it("skips a project with no authentication library: no per-user data to reach", () => {
    const demo = projectFile({ express: "4", "@prisma/client": "5" }, "src/index.js");
    expect(n(`app.get("/post/:id", handler);`, demo, a)).toBe(0);
  });

  it("recognises ownership checks hidden behind a helper's name", () => {
    const file = cookieProjectFile("server.js");
    const nextFile = cookieProjectFile("app/api/posts/[postId]/route.ts");
    expect(n(`export async function DELETE(req, ctx) { if (!(await verifyCurrentUserHasAccessToPost(ctx.params.postId))) return new Response(null, { status: 403 }); }`, nextFile, a)).toBe(0);
    expect(n(`app.put("/api/BasketItems/:id", security.appendUserId(), handler);`, file, a)).toBe(0);
    expect(n(`app.get("/x/:id", checkOwnership, handler);`, file, a)).toBe(0);
    expect(n(`app.get("/x/:id", handler);`, file, a)).toBe(1);
  });

  it("skips a route that a deny-everything middleware switches off", () => {
    expect(n(`app.put("/api/Feedbacks/:id", security.denyAll());`, cookieProjectFile("server.js"), a)).toBe(0);
  });

  it("skips a Next.js handler that takes no arguments (it cannot read the id)", () => {
    const file = cookieProjectFile("app/api/chat/[id]/stream/route.ts");
    expect(n(`export function GET() { return new Response(null, { status: 204 }); }`, file, a)).toBe(0);
    expect(n(`export function GET(req, ctx) { return db.chat.find(ctx.params.id); }`, file, a)).toBe(1);
  });
});

describe("hardcoded-secret: values that are not credentials", () => {
  const a = [new HardcodedSecretAnalyzer()];

  it("ignores error codes and token types written in camelCase / PascalCase", () => {
    expect(n(`throw fail({ password: "incorrectPassword", oldPassword: "missingOldPassword" });`, "auth.ts", a)).toBe(0);
    expect(n(`const tokenTypes = { RESET_PASSWORD: "resetPassword", VERIFY_EMAIL: "verifyEmail" };`, "tokens.js", a)).toBe(0);
    expect(n(`const t = { password: "MissingOldPassword" };`, "x.ts", a)).toBe(0);
    // ...but a passphrase that merely looks like words is still a hard-coded credential.
    expect(n(`class Login { public testingPassword = "IamUsedForTesting"; }`, "login.component.ts", a)).toBe(1);
  });

  it("ignores password hashes in seed files", () => {
    const bcrypt = "$2a$10$" + "TLtC603wy85MM./ot/pvEec0w2au6sjPaOmLpLQFbxPdpJH9fDwwS".slice(0, 53);
    expect(n(`await prisma.user.create({ data: { password: "${bcrypt}" } });`, "seed.ts", a)).toBe(0);
    expect(n(`const u = { passwordHash: "$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$RdescudvJCsgt3ub" };`, "seed.ts", a)).toBe(0);
  });

  it("ignores a list of placeholder values the program REJECTS at start-up", () => {
    const source = `const PLACEHOLDER_SECRETS = { AUTH_JWT_SECRET: "secret", AUTH_REFRESH_SECRET: "secret_for_refresh" };`;
    expect(n(source, "auth.config.ts", a)).toBe(0);
    expect(n(`const config = { jwtSecret: "secret" };`, "auth.config.ts", a)).toBe(1);
  });
});

describe("username-enumeration needs a login flow", () => {
  const a = [new UsernameEnumerationAnalyzer()];

  it("does not treat a change-password handler as login", () => {
    const source = `
      async function update(user, dto) {
        if (!current) throw new Error("userNotFound");
        if (!ok) throw new Error("incorrectOldPassword");
      }`;
    expect(n(source, "profile.service.ts", a)).toBe(0);
  });

  it("recognises a login handler whose route path sits outside the function", () => {
    const source = `
      app.post("/login", async (req, res) => {
        if (!user) return res.send("Invalid username");
        if (!ok) return res.send("Invalid password");
      });`;
    expect(n(source, "routes.js", a)).toBe(1);
  });
});

describe("only the arguments that matter count as the dangerous ones", () => {
  it("open redirect: a tainted cookie VALUE is not a tainted redirect TARGET", () => {
    const source = `
      export async function setTheme(request) {
        const theme = (await request.formData()).get("theme");
        const back = "/";
        return redirect(back, { headers: { "Set-Cookie": await themeCookie.serialize(theme) } });
      }`;
    expect(n(source, "theme.ts", [new OpenRedirectAnalyzer()])).toBe(0);
    expect(n(`export async function GET(request) { const to = new URL(request.url).searchParams.get("to"); return redirect(to, { status: 302 }); }`, "route.ts", [new OpenRedirectAnalyzer()])).toBe(1);
  });

  it("SQL: values bound as parameters are safe, even when the query is a template literal", () => {
    const a = [new SqlInjectionAnalyzer()];
    expect(n("app.get('/u', (req, res) => { db.query(`SELECT * FROM u WHERE id = $1`, [req.query.id]); });", "app.js", a)).toBe(0);
    expect(n("app.get('/u', (req, res) => { sequelize.query(`SELECT * FROM u WHERE id = :id`, { replacements: { id: req.query.id } }); });", "app.js", a)).toBe(0);
    expect(n("app.get('/u', (req, res) => { db.query(`SELECT * FROM u WHERE id = ${req.query.id}`); });", "app.js", a)).toBe(1);
  });

  it("path traversal: tainted file CONTENT is not a tainted path", () => {
    const a = [new PathTraversalAnalyzer()];
    expect(n(`app.post("/u", (req, res) => { fs.writeFile("/srv/uploads/fixed.bin", req.body.data, cb); });`, "app.js", a)).toBe(0);
    expect(n(`app.get("/v", (req, res) => { const range = req.headers.range; fs.createReadStream(videoPath(), { start: range }); });`, "app.js", a)).toBe(0);
    expect(n(`app.post("/u", (req, res) => { fs.writeFile("/srv/uploads/" + req.body.name, "x", cb); });`, "app.js", a)).toBe(1);
  });
});

describe("values that went through a cleaning step or an allowlist", () => {
  const sql = [new SqlInjectionAnalyzer()];

  it("a hashed value cannot inject: `${hash(req.body.password)}`", () => {
    const source = "app.post('/l', (req, res) => { db.query(`SELECT * FROM u WHERE p = '${security.hash(req.body.password || '')}'`); });";
    expect(n(source, "app.js", sql)).toBe(0);
  });

  it("numeric coercion and escaping clean the value, but String() does not", () => {
    expect(n("app.get('/a', (req, res) => { db.query(`SELECT ${parseInt(req.query.n, 10)}`); });", "app.js", sql)).toBe(0);
    expect(n("app.get('/a', (req, res) => { db.query(`SELECT ${mysql.escape(req.query.n)}`); });", "app.js", sql)).toBe(0);
    expect(n("app.get('/a', (req, res) => { db.query(`SELECT ${String(req.query.n)}`); });", "app.js", sql)).toBe(1);
  });

  it("a value checked against a list before use is not attacker-controlled", () => {
    const source = `
      app.post("/u", (req, res) => {
        const url = req.body.imageUrl;
        const ext = ["jpg", "png"].includes(url.split(".").pop()) ? url.split(".").pop() : "jpg";
        fs.createWriteStream("/srv/uploads/" + id + "." + ext);
      });`;
    expect(n(source, "app.js", [new PathTraversalAnalyzer()])).toBe(0);
  });
});

describe("path traversal covers the file-serving calls too", () => {
  const a = [new PathTraversalAnalyzer()];

  it("flags res.sendFile / res.download with a user-controlled path (OWASP Juice Shop fileServer)", () => {
    expect(n(`app.get("/ftp/:file", (req, res) => { const file = req.params.file; res.sendFile(path.resolve("ftp/", file)); });`, "app.js", a)).toBe(1);
    expect(n(`app.get("/d", (req, res) => { res.download(req.query.name); });`, "app.js", a)).toBe(1);
    expect(n(`app.get("/d", (req, res) => { res.sendFile(path.join(__dirname, "index.html")); });`, "app.js", a)).toBe(0);
  });

  it("flags directory listing / removal calls", () => {
    expect(n(`app.get("/l", (req, res) => { fs.readdir(req.query.dir, cb); });`, "app.js", a)).toBe(1);
    expect(n(`app.delete("/f", (req, res) => { fs.rm(req.body.file); });`, "app.js", a)).toBe(1);
  });

  it("command injection still flags exec with a tainted command (control)", () => {
    expect(n(`app.get("/p", (req, res) => { exec("ping " + req.query.host); });`, "app.js", [new CommandInjectionAnalyzer()])).toBe(1);
  });
});

describe("request data that arrives as handler parameters or in other frameworks", () => {
  it("destructured request parameters are input: `({ file }: Request, res)` (OWASP Juice Shop XXE upload)", () => {
    const source = `
      async function handleXmlUpload({ file }: Request, res: Response) {
        const data = file.buffer.toString();
        libxml.parseXml(data, { noent: true });
      }`;
    expect(n(source, "fileUpload.ts", [new XxeAnalyzer()])).toBe(1);
  });

  it("only the parts of the request that matter for the rule: a header is not a MongoDB filter object", () => {
    const source = `async function find({ headers, body }: Request, res: Response) { await User.findOne({ token: headers.token }); }`;
    expect(n(source, "a.ts", [new NoSqlInjectionAnalyzer()])).toBe(0);
    expect(n(`async function find({ body }: Request, res: Response) { await User.findOne({ name: body.name }); }`, "a.ts", [new NoSqlInjectionAnalyzer()])).toBe(1);
  });

  it("does not treat an arbitrary function's destructured argument as a request", () => {
    expect(n(`function Card({ body, query }) { db.query("SELECT " + body + query); }`, "card.js", [new SqlInjectionAnalyzer()])).toBe(0);
  });

  it("Next.js route params arrive as the second argument: GET(request, { params })", () => {
    const source = "export async function GET(request: Request, { params }: { params: { id: string } }) { return db.query(`SELECT * FROM t WHERE id = ${params.id}`); }";
    expect(n(source, "app/api/t/[id]/route.ts", [new SqlInjectionAnalyzer()])).toBe(1);
    const async15 = "export async function GET(request: Request, { params }: Ctx) { const { id } = await params; return db.query(`SELECT * FROM t WHERE id = ${id}`); }";
    expect(n(async15, "app/api/t/[id]/route.ts", [new SqlInjectionAnalyzer()])).toBe(1);
  });

  it("Remix loaders: ({ request, params })", () => {
    const source = "export async function loader({ request, params }: LoaderFunctionArgs) { return db.query(`SELECT * FROM t WHERE id = ${params.id}`); }";
    expect(n(source, "routes/t.$id.tsx", [new SqlInjectionAnalyzer()])).toBe(1);
  });

  it("Fastify (request.query), Koa (ctx.query / ctx.request.body) and Hono (c.req.query())", () => {
    const a = [new SqlInjectionAnalyzer()];
    expect(n("fastify.get('/u', async (request) => { return db.query(`SELECT ${request.query.id}`); });", "a.js", a)).toBe(1);
    expect(n("router.get('/u', async (ctx) => { ctx.body = await db.query(`SELECT ${ctx.query.id}`); });", "a.js", a)).toBe(1);
    expect(n("router.post('/u', async (ctx) => { await db.query(`SELECT ${ctx.request.body.id}`); });", "a.js", a)).toBe(1);
    expect(n("app.get('/u', async (c) => { return c.json(await db.query(`SELECT ${c.req.query('id')}`)); });", "a.js", a)).toBe(1);
    expect(n("app.post('/u', async (c) => { const { id } = await c.req.json(); await db.query(`SELECT ${id}`); });", "a.js", a)).toBe(1);
  });

  it("follows a destructured parameter into a helper in another function", () => {
    const source = `
      function lookup(name) { return db.query("SELECT * FROM t WHERE n = '" + name + "'"); }
      async function handler({ query }: Request, res: Response) { return lookup(query.name); }`;
    expect(n(source, "a.ts", [new SqlInjectionAnalyzer()])).toBe(1);
  });
});

describe("found while dogfooding the Supabase fixture", () => {
  it("a `secret` property is a signing secret only in calls about sessions / tokens / auth", () => {
    const a = [new HardcodedSecretAnalyzer()];
    expect(n(`return Response.json({ secret: "admin data" });`, "route.ts", a)).toBe(0);
    expect(n(`app.use(session({ secret: "keyboard cat" }));`, "app.js", a)).toBe(1);
    expect(n(`export default NextAuth({ secret: "hunter22" });`, "auth.ts", a)).toBe(1);
    expect(n(`app.use(expressjwt({ secret: "abc12345", algorithms: ["HS256"] }));`, "app.js", a)).toBe(1);
  });

  it("supabase.auth.getUser() / getSession() and Firebase verifyIdToken count as an access check", async () => {
    const { scanSource } = await import("../src/index");
    const { BrokenAccessControlAnalyzer } = await import("../src/analyzers/broken-access-control");
    const flagged = (source: string, file: string) => scanSource(source, file, [new BrokenAccessControlAnalyzer()]).findings.length;
    expect(flagged(`export async function GET() { const { data } = await supabase.auth.getUser(); if (!data.user) return new Response(null, { status: 401 }); return Response.json({}); }`, "app/api/admin/route.ts")).toBe(0);
    expect(flagged(`export async function GET() { return Response.json({ all: "users" }); }`, "app/api/admin/route.ts")).toBe(1);
    expect(flagged(`app.get("/admin/users", async (req, res) => { const decoded = await admin.auth().verifyIdToken(req.headers.authorization); res.json({}); });`, "server.js")).toBe(0);
  });
});
