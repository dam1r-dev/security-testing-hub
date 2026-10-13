import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { scanPath } from "../src/index";

// Regression cases from the validation round on 16 real Supabase / Firebase projects (docs/validation.md, Round 9):
// each one is a false positive that the first pass produced on real code, with a control that must still fire.

const dirs: string[] = [];
afterAll(() => dirs.forEach((d) => fs.rmSync(d, { recursive: true, force: true })));

function project(files: Record<string, string>): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "sh-round9-"));
  dirs.push(dir);
  for (const [name, content] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(dir, name)), { recursive: true });
    fs.writeFileSync(path.join(dir, name), content);
  }
  return dir;
}

const found = (dir: string, ruleId: string) => scanPath(dir).results.flatMap((r) => r.findings).filter((f) => f.ruleId === ruleId);
const pkg = (dependencies: Record<string, string>) => JSON.stringify({ dependencies });

describe("IDOR: ownership can be checked where the route's handler lives", () => {
  const routes = `const express = require("express");\nconst router = express.Router();\nconst Users = require("./controller");\nrouter.get("/users/:userId", Users.getUser);\nmodule.exports = router;\n`;
  const session = { "package.json": pkg({ express: "4", "express-session": "1" }) };

  it("is quiet when the controller compares the requester with the id", () => {
    const dir = project({
      ...session,
      "routes.js": routes,
      "controller.js": `async function getUser(req, res) {\n  const requester = req.user;\n  if (requester.id !== req.params.userId) return res.status(403).end();\n  res.json(await db.find(req.params.userId));\n}\nmodule.exports = { getUser };\n`,
    });
    expect(found(dir, "idor")).toHaveLength(0);
  });

  it("still reports the route when the controller never looks at the caller", () => {
    const dir = project({
      ...session,
      "routes.js": routes,
      "controller.js": `async function getUser(req, res) {\n  res.json(await db.find(req.params.userId));\n}\nmodule.exports = { getUser };\n`,
    });
    expect(found(dir, "idor")).toHaveLength(1);
  });

  it("is quiet for routes behind an explicit role check (the role model is the developer's decision)", () => {
    const dir = project({
      ...session,
      "routes.js": `const router = require("express").Router();\nrouter.get("/countries/:id", authenticate, checkRole(['Admin', 'Manager']), ctl.getById);\nrouter.delete("/cards/:cardId", authenticate, authorize('ADMIN'), ctl.remove);\n`,
    });
    expect(found(dir, "idor")).toHaveLength(0);
  });

  it("is quiet in a Next route whose local helper does the session and membership check", () => {
    const helper = `import { auth } from "@/lib/auth";\nasync function authorize(id: string) {\n  const session = await auth();\n  if (!session?.user?.id) return { error: "no" };\n  return { session };\n}\n`;
    const dir = project({
      "package.json": pkg({ next: "15", "next-auth": "5" }),
      "app/api/workspaces/[workspaceId]/items/route.ts": `${helper}export async function GET(request: Request, { params }: { params: Promise<{ workspaceId: string }> }) {\n  const { workspaceId } = await params;\n  const access = await authorize(workspaceId);\n  return Response.json(await db.get(workspaceId));\n}\n`,
      "app/api/workspaces/[workspaceId]/open/route.ts": `export async function GET(request: Request, { params }: { params: Promise<{ workspaceId: string }> }) {\n  const { workspaceId } = await params;\n  return Response.json(await db.get(workspaceId));\n}\n`,
    });
    const files = found(dir, "idor").map((f) => path.basename(path.dirname(f.location.file)));
    expect(files).toEqual(["open"]);
  });
});

describe("CSRF: look at the project, not just the file", () => {
  const routes = `const router = require("express").Router();\nrouter.post("/items", (req, res) => res.json({ user: req.session.user }));\nmodule.exports = router;\n`;

  it("is quiet when a csrf middleware is registered in another file", () => {
    const dir = project({
      "package.json": pkg({ express: "4", "express-session": "1" }),
      "app.js": `const app = require("express")();\nconst { verifyCsrf } = require("./csrf");\napp.use(verifyCsrf);\n`,
      "routes.js": routes,
    });
    expect(found(dir, "csrf")).toHaveLength(0);
  });

  it("still reports cookie-session routes with no csrf anywhere", () => {
    const dir = project({ "package.json": pkg({ express: "4", "express-session": "1" }), "routes.js": routes });
    expect(found(dir, "csrf")).toHaveLength(1);
  });

  it("is quiet when a session library is installed but the app authenticates with the Authorization header", () => {
    const dir = project({
      "package.json": pkg({ express: "4", "cookie-session": "2", jsonwebtoken: "9" }),
      "auth.js": `module.exports = (req, res, next) => { const token = (req.headers['authorization'] || '').split(' ')[1]; next(); };\n`,
      "routes.js": `const router = require("express").Router();\nrouter.post("/items", (req, res) => res.json({}));\n`,
    });
    expect(found(dir, "csrf")).toHaveLength(0);
  });

  it("is quiet for an app whose only auth is the Firebase / Supabase client (a token in the page, not a cookie)", () => {
    for (const dep of ["firebase", "@supabase/supabase-js"]) {
      const dir = project({
        "package.json": pkg({ next: "15", [dep]: "1" }),
        "app/api/copilot/route.ts": `export async function POST(request: Request) { return Response.json({ ok: true }); }\n`,
      });
      expect(found(dir, "csrf")).toHaveLength(0);
    }
  });
});

describe("broken-access-control: a shared-secret check is an access check", () => {
  it("accepts a secret header compared with an environment variable", () => {
    const dir = project({
      "package.json": pkg({ express: "4" }),
      "app.js": `const app = require("express")();\napp.post("/internal/jobs", (req, res) => {\n  if (req.headers["x-job-secret"] !== process.env.JOB_SECRET) return res.status(401).end();\n  res.end();\n});\n`,
    });
    expect(found(dir, "broken-access-control")).toHaveLength(0);
  });

  it("still reports an internal route with no check", () => {
    const dir = project({ "package.json": pkg({ express: "4" }), "app.js": `const app = require("express")();\napp.post("/internal/jobs", (req, res) => res.end());\n` });
    expect(found(dir, "broken-access-control")).toHaveLength(1);
  });
});

describe("supabase-auth: getSession() is only a problem on a server", () => {
  const code = `import { createClient } from "@supabase/supabase-js";\nconst supabase = createClient(url, key);\nexport async function who() { const { data } = await supabase.auth.getSession(); return data.session; }\n`;

  it("is quiet in browser code (a hook, a context, a single-page app)", () => {
    const dir = project({ "package.json": pkg({ react: "18", "@supabase/supabase-js": "2" }), "src/hooks/useAuth.ts": code, "src/context/AuthContext.tsx": code });
    expect(found(dir, "supabase-auth")).toHaveLength(0);
  });

  it("reports it in a route handler and in code that imports server-only modules", () => {
    const dir = project({
      "package.json": pkg({ next: "15", "@supabase/supabase-js": "2" }),
      "app/api/me/route.ts": code,
      "lib/session.ts": `import { cookies } from "next/headers";\n${code}`,
    });
    expect(found(dir, "supabase-auth")).toHaveLength(2);
  });
});

describe("supabase-rls: a server-only app does not publish the anon key", () => {
  const migration = { "supabase/migrations/001_init.sql": "create table public.items (id int primary key, title text);\n" };

  it("lowers the table finding when only the service-role key is used on a server", () => {
    const dir = project({
      "package.json": pkg({ express: "4", "@supabase/supabase-js": "2" }),
      ...migration,
      "src/db.js": `const { createClient } = require("@supabase/supabase-js");\nmodule.exports = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY);\n`,
    });
    const [finding] = found(dir, "supabase-rls");
    expect(finding).toMatchObject({ severity: "medium", confidence: "low" });
    expect(finding?.message).toContain("only from a server");
  });

  it("stays critical when the browser gets the anon key, or when no client code is seen at all", () => {
    const shipped = project({
      "package.json": pkg({ next: "15", "@supabase/supabase-js": "2" }),
      ...migration,
      "lib/supabase.ts": `import { createClient } from "@supabase/supabase-js";\nexport const supabase = createClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!);\n`,
    });
    expect(found(shipped, "supabase-rls")[0]?.severity).toBe("critical");
    const unknown = project({ "package.json": pkg({ "@supabase/supabase-js": "2" }), ...migration });
    expect(found(unknown, "supabase-rls")[0]?.severity).toBe("critical");
  });
});
