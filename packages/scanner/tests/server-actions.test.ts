import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { defaultAnalyzers, scanPath, scanSource } from "../src/index";

// Next.js Server Actions ("use server"): public POST endpoints whose arguments come from the browser.

const dirs: string[] = [];
afterAll(() => dirs.forEach((d) => fs.rmSync(d, { recursive: true, force: true })));

function project(files: Record<string, string>): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "sh-actions-"));
  dirs.push(dir);
  fs.writeFileSync(path.join(dir, "package.json"), JSON.stringify({ dependencies: { next: "15", "@prisma/client": "5" } }));
  for (const [name, content] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(dir, name)), { recursive: true });
    fs.writeFileSync(path.join(dir, name), content);
  }
  return dir;
}
const found = (dir: string, ruleId: string) => scanPath(dir).results.flatMap((r) => r.findings).filter((f) => f.ruleId === ruleId);
const inline = (code: string, ruleId: string) => scanSource(code, "actions.ts", defaultAnalyzers()).findings.filter((f) => f.ruleId === ruleId);

describe("Server Actions that change data without checking the caller", () => {
  it("reports an exported action that writes to the database and never looks at the session", () => {
    const code = `"use server";\nimport { prisma } from "@/lib/db";\nexport async function deletePost(id: string) {\n  await prisma.post.delete({ where: { id } });\n}\n`;
    const [finding] = inline(code, "broken-access-control");
    expect(finding).toMatchObject({ severity: "high", confidence: "medium" });
    expect(finding?.message).toContain("deletePost");
    expect(finding?.message).toContain("public POST endpoint");
  });

  it("is quiet when the action checks the session first", () => {
    for (const check of [`const session = await auth();`, `const { data: { user } } = await supabase.auth.getUser();`, `const user = await getCurrentUser();`, `const s = await getServerSession();`]) {
      const code = `"use server";\nexport async function savePost(title: string) {\n  ${check}\n  if (!user && !session && !s) throw new Error("no");\n  await prisma.post.create({ data: { title, userId: "x" } });\n}\n`;
      expect(inline(code, "broken-access-control")).toHaveLength(0);
    }
  });

  it("is quiet when the check lives in a helper in another file", () => {
    const dir = project({
      "lib/guard.ts": `export async function requireUser() {\n  const session = await auth();\n  if (!session) throw new Error("no");\n  return session.user;\n}\n`,
      "app/actions.ts": `"use server";\nimport { requireUser } from "@/lib/guard";\nexport async function savePost(title: string) {\n  await requireUser();\n  await prisma.post.create({ data: { title } });\n}\n`,
      "app/open.ts": `"use server";\nexport async function savePost2(title: string) {\n  await prisma.post.create({ data: { title } });\n}\n`,
    });
    const files = found(dir, "broken-access-control").map((f) => path.basename(f.location.file));
    expect(files).toEqual(["open.ts"]);
  });

  it("skips actions that are meant to run before sign-in, and non-mutating ones", () => {
    for (const name of ["login", "signUp", "subscribeToNewsletter", "contactUs", "resetPassword"]) {
      expect(inline(`"use server";\nexport async function ${name}(f: FormData) { await prisma.user.create({ data: {} }); }\n`, "broken-access-control")).toHaveLength(0);
    }
    expect(inline(`"use server";\nexport async function getPosts() { return prisma.post.findMany(); }\n`, "broken-access-control")).toHaveLength(0);
  });

  it("understands an inline directive, and ignores helpers that are not exported or files without the directive", () => {
    expect(inline(`export default function Page() {\n  async function remove(id: string) {\n    "use server";\n    await prisma.post.delete({ where: { id } });\n  }\n  return null;\n}\n`, "broken-access-control")).toHaveLength(1);
    expect(inline(`"use server";\nasync function helper(id: string) { await prisma.post.delete({ where: { id } }); }\nexport async function ok() { await auth(); }\n`, "broken-access-control")).toHaveLength(0);
    expect(inline(`export async function plain(id: string) { await prisma.post.delete({ where: { id } }); }\n`, "broken-access-control")).toHaveLength(0);
  });

  it("understands arrow-function actions and default exports", () => {
    expect(inline(`"use server";\nexport const removeAll = async () => { await prisma.post.deleteMany(); };\n`, "broken-access-control")).toHaveLength(1);
    expect(inline(`"use server";\nexport default async function wipe() { await db.todo.deleteMany(); }\n`, "broken-access-control")).toHaveLength(1);
  });
});

describe("Server Actions that trust the id the browser sent", () => {
  it("reports a signed-in action that deletes by id without comparing it with the caller", () => {
    const code = `"use server";\nexport async function removeTodo(id: string) {\n  const { userId } = await auth();\n  if (!userId) throw new Error("no");\n  await prisma.todo.delete({ where: { id } });\n}\n`;
    const [finding] = inline(code, "idor");
    expect(finding).toMatchObject({ severity: "high", confidence: "low" });
    expect(finding?.message).toContain("removeTodo");
  });

  it("also finds the id inside formData", () => {
    const code = `"use server";\nexport async function renameTodo(formData: FormData) {\n  const { userId } = await auth();\n  if (!userId) throw new Error("no");\n  await prisma.todo.update({ where: { id: formData.get("todoId") as string }, data: { title: "x" } });\n}\n`;
    expect(inline(code, "idor")).toHaveLength(1);
  });

  it("is quiet when the query is scoped to the caller, or ownership is checked first", () => {
    const scoped = `"use server";\nexport async function removeTodo(id: string) {\n  const { userId } = await auth();\n  await prisma.todo.delete({ where: { id, userId } });\n}\n`;
    expect(inline(scoped, "idor")).toHaveLength(0);
    const checked = `"use server";\nexport async function removeTodo(id: string) {\n  const session = await auth();\n  const todo = await prisma.todo.findUnique({ where: { id } });\n  if (todo?.ownerId !== session?.user?.id) throw new Error("no");\n  await prisma.todo.delete({ where: { id } });\n}\n`;
    expect(inline(checked, "idor")).toHaveLength(0);
    const helper = `"use server";\nexport async function removeTodo(id: string) {\n  await auth();\n  await verifyTodoOwnership(id);\n  await prisma.todo.delete({ where: { id } });\n}\n`;
    expect(inline(helper, "idor")).toHaveLength(0);
  });

  it("does not add an idor finding on top of the missing-auth one", () => {
    const code = `"use server";\nexport async function removeTodo(id: string) {\n  await prisma.todo.delete({ where: { id } });\n}\n`;
    expect(inline(code, "idor")).toHaveLength(0);
    expect(inline(code, "broken-access-control")).toHaveLength(1);
  });
});

describe("the arguments of a Server Action are request input for the data-flow rules", () => {
  it("SQL injection through a plain argument and through formData", () => {
    expect(inline(`"use server";\nexport async function find(name: string) {\n  await auth();\n  return db.query("SELECT * FROM t WHERE n = '" + name + "'");\n}\n`, "sql-injection")).toHaveLength(1);
    expect(inline(`"use server";\nexport async function find(prev: unknown, formData: FormData) {\n  await auth();\n  const name = formData.get("name");\n  return db.query(\`SELECT * FROM t WHERE n = '\${name}'\`);\n}\n`, "sql-injection")).toHaveLength(1);
  });

  it("command injection and open redirect", () => {
    expect(inline(`"use server";\nimport { exec } from "child_process";\nexport async function run(formData: FormData) { await auth(); exec(formData.get("cmd") as string); }\n`, "command-injection")).toHaveLength(1);
    expect(inline(`"use server";\nimport { redirect } from "next/navigation";\nexport async function go(formData: FormData) { await auth(); const to = formData.get("to") as string; redirect(to); }\n`, "open-redirect")).toHaveLength(1);
  });

  it("a parameterised query and a function outside a use-server file stay quiet", () => {
    expect(inline(`"use server";\nexport async function find(name: string) { await auth(); return db.query("SELECT * FROM t WHERE n = $1", [name]); }\n`, "sql-injection")).toHaveLength(0);
    expect(inline(`export async function find(name: string) { return db.query("SELECT * FROM t WHERE n = '" + name + "'"); }\n`, "sql-injection")).toHaveLength(0);
  });
});
