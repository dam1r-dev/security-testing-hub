import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { scanPath, scanSource } from "../src";

jest.setTimeout(60_000);

const FIXTURE = path.resolve(__dirname, "../../../examples/vulnerable-frameworks");

function found(summary: ReturnType<typeof scanPath>, root: string): string[] {
  return summary.results
    .flatMap((r) => r.findings.map((f) => `${path.relative(root, r.file).split(path.sep).join("/")}:${f.location.startLine}:${f.ruleId}`))
    .sort();
}

describe("SvelteKit, Remix, Nuxt, tRPC and Hono handlers (examples/vulnerable-frameworks)", () => {
  const result = found(scanPath(FIXTURE, { config: false }), FIXTURE);

  it("finds SQL injection from every framework's way of reading the request", () => {
    expect(result).toEqual(
      expect.arrayContaining([
        "src/routes/api/search/+server.ts:7:sql-injection", // SvelteKit: url.searchParams.get
        "src/routes/api/search/+server.ts:13:sql-injection", // SvelteKit: { params } on its own
        "app/routes/users.$id.tsx:4:sql-injection", // Remix loader({ params })
        "server/api/orders.post.ts:6:sql-injection", // Nuxt: getQuery(event) / readBody(event)
        "src/server/post.ts:7:sql-injection", // tRPC: { input } into $queryRawUnsafe
        "hono/index.ts:6:sql-injection", // Hono: c.req.query
        "hono/index.ts:11:path-traversal", // Hono: c.req.param
      ]),
    );
  });

  it("does not flag the safe handlers: parameterised query, signed-in and owner-scoped, session helper", () => {
    expect(result.some((r) => r.startsWith("src/routes/api/search/+server.ts:2") && /sql/.test(r))).toBe(false); // the PUT with $1 / $2
    expect(result.filter((r) => r.startsWith("src/routes/api/search/+server.ts"))).toHaveLength(2);
    expect(result.some((r) => r.startsWith("server/api/me.get.ts"))).toBe(false); // requireUserSession(event)
    expect(result.some((r) => r.startsWith("src/server/post.ts:2") && /idor|broken/.test(r))).toBe(false); // protected + scoped to ctx.session.user.id
    // the input of a validated tRPC procedure is a string: it is not a NoSQL operator injection
    expect(result.some((r) => /nosql/.test(r))).toBe(false);
  });

  it("reports handlers that change data without checking the caller, and a signed-in user changing someone else's record", () => {
    expect(result).toEqual(
      expect.arrayContaining([
        "src/server/post.ts:10:broken-access-control", // publicProcedure.mutation
        "src/server/post.ts:15:idor", // protectedProcedure, input.id not tied to ctx.session
        "src/routes/posts/[id]/+page.server.ts:5:broken-access-control", // SvelteKit action "remove"
        "app/routes/users.$id.tsx:8:broken-access-control", // Remix action
        "server/api/orders.post.ts:3:broken-access-control", // Nuxt handler
      ]),
    );
    // the SvelteKit action that checks locals.user and scopes the query to it is fine
    expect(result.filter((r) => r.startsWith("src/routes/posts/[id]/+page.server.ts"))).toHaveLength(1);
  });

  it("a hook or middleware that stops anonymous requests for the whole project counts as the check", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "hub-fw-"));
    fs.mkdirSync(path.join(dir, "src/routes/items"), { recursive: true });
    fs.writeFileSync(path.join(dir, "package.json"), "{}");
    fs.writeFileSync(
      path.join(dir, "src/routes/items/+server.ts"),
      "export async function POST({ request }) {\n  const body = await request.json();\n  await db.item.create({ data: body });\n  return new Response('ok');\n}\n",
    );
    const before = found(scanPath(dir, { config: false }), dir);
    expect(before).toContain("src/routes/items/+server.ts:1:broken-access-control");

    fs.writeFileSync(
      path.join(dir, "src/hooks.server.ts"),
      "export async function handle({ event, resolve }) {\n  const session = await getSession(event);\n  if (!session) throw redirect(303, '/login');\n  event.locals.user = session.user;\n  return resolve(event);\n}\n",
    );
    expect(found(scanPath(dir, { config: false }), dir).some((r) => /broken-access-control/.test(r))).toBe(false);
  });

  it("routes that are public on purpose (login, contact, webhooks) are left alone", () => {
    const code = "export default defineEventHandler(async (event) => {\n  const body = await readBody(event);\n  await db.message.create({ data: body });\n});\n";
    expect(scanSource(code, "/app/server/api/contact.post.ts").findings.some((f) => f.ruleId === "broken-access-control")).toBe(false);
    expect(scanSource(code, "/app/server/api/notes.post.ts").findings.some((f) => f.ruleId === "broken-access-control")).toBe(true);
  });
});

describe("Prisma raw queries", () => {
  const flagged = (code: string): string[] => scanSource(code, "/app/api.ts").findings.filter((f) => f.ruleId === "sql-injection").map((f) => f.sinkSnippet);

  it("$queryRawUnsafe and $executeRawUnsafe with request data are SQL injection", () => {
    expect(flagged("export async function GET(request: Request) {\n  const q = new URL(request.url).searchParams.get('q');\n  return prisma.$queryRawUnsafe(`SELECT * FROM t WHERE n = '${q}'`);\n}\n")).toHaveLength(1);
    expect(flagged("app.post('/x', async (req, res) => {\n  await prisma.$executeRawUnsafe('DELETE FROM t WHERE id = ' + req.body.id);\n});\n")).toHaveLength(1);
  });

  it("the tagged template $queryRaw`...` binds its values and is not flagged; a hand-built string passed to it is", () => {
    expect(flagged("app.get('/x', async (req, res) => {\n  res.json(await prisma.$queryRaw`SELECT * FROM t WHERE id = ${req.query.id}`);\n});\n")).toHaveLength(0);
    expect(flagged("app.get('/x', async (req, res) => {\n  res.json(await prisma.$queryRaw('SELECT * FROM t WHERE id = ' + req.query.id));\n});\n")).toHaveLength(1);
  });
});
