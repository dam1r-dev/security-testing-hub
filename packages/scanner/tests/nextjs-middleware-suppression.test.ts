import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { scanPath } from "../src/index";
import { BrokenAccessControlAnalyzer } from "../src/analyzers/broken-access-control";

// hasNearbyMiddlewareWithAuthHint() needs real files on disk to walk up from,
// so this exercises it against a temp project instead of an in-memory scanSource().
describe("BrokenAccessControlAnalyzer + nearby middleware.ts", () => {
  let projectDir: string;

  beforeEach(() => {
    projectDir = fs.mkdtempSync(path.join(os.tmpdir(), "security-hub-mw-test-"));
    fs.writeFileSync(path.join(projectDir, "package.json"), "{}");
    fs.mkdirSync(path.join(projectDir, "app", "admin", "users"), { recursive: true });
    fs.writeFileSync(
      path.join(projectDir, "app", "admin", "users", "route.ts"),
      `export async function GET() { return Response.json(await db.user.findMany()); }`,
    );
  });

  afterEach(() => {
    fs.rmSync(projectDir, { recursive: true, force: true });
  });

  it("flags the admin route when there is no middleware.ts at all", () => {
    const summary = scanPath(projectDir, { analyzers: [new BrokenAccessControlAnalyzer()] });
    expect(summary.findingsCount).toBe(1);
  });

  it("does not flag it when a project-root middleware.ts mentions an auth check", () => {
    fs.writeFileSync(
      path.join(projectDir, "middleware.ts"),
      `
      import { getServerSession } from "./lib/auth";
      export async function middleware(request) {
        const session = await getServerSession();
        if (!session) return new Response(null, { status: 401 });
      }
      export const config = { matcher: ["/admin/:path*"] };
      `,
    );
    const summary = scanPath(projectDir, { analyzers: [new BrokenAccessControlAnalyzer()] });
    expect(summary.findingsCount).toBe(0);
  });

  it("still flags it when middleware.ts exists but has no recognizable auth check", () => {
    fs.writeFileSync(
      path.join(projectDir, "middleware.ts"),
      `export function middleware(request) { console.log("hit", request.url); }`,
    );
    const summary = scanPath(projectDir, { analyzers: [new BrokenAccessControlAnalyzer()] });
    expect(summary.findingsCount).toBe(1);
  });
});
