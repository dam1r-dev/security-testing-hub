import { scanSource } from "../src/index";
import { IdorAnalyzer } from "../src/analyzers/idor";
import { BrokenAccessControlAnalyzer } from "../src/analyzers/broken-access-control";
import { CsrfAnalyzer } from "../src/analyzers/csrf";

describe("IdorAnalyzer on Next.js App Router routes", () => {
  const analyzers = [new IdorAnalyzer()];

  it("flags a [id]-segment route with no session/ownership check", () => {
    const source = `
      export async function GET(request, { params }) {
        const account = await db.account.findUnique({ where: { id: params.accountId } });
        return Response.json(account);
      }
    `;
    const result = scanSource(source, "app/api/accounts/[accountId]/route.ts", analyzers);
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]?.ruleId).toBe("idor");
  });

  it("does not flag when the handler checks the session", () => {
    const source = `
      export async function GET(request, { params }) {
        const session = await getServerSession(authOptions);
        const account = await db.account.findUnique({ where: { id: params.accountId } });
        if (account.ownerId !== session.user.id) return new Response(null, { status: 403 });
        return Response.json(account);
      }
    `;
    const result = scanSource(source, "app/api/accounts/[accountId]/route.ts", analyzers);
    expect(result.findings).toHaveLength(0);
  });

  it("does not flag routes without an id-like dynamic segment", () => {
    const source = `
      export async function GET() {
        return Response.json(await db.account.findMany());
      }
    `;
    const result = scanSource(source, "app/api/accounts/route.ts", analyzers);
    expect(result.findings).toHaveLength(0);
  });

  it("does not flag a catch-all segment as id-like", () => {
    const source = `
      export async function GET(request, { params }) {
        return Response.json(await getFile(params.slug));
      }
    `;
    const result = scanSource(source, "app/files/[...slug]/route.ts", analyzers);
    expect(result.findings).toHaveLength(0);
  });
});

describe("BrokenAccessControlAnalyzer on Next.js App Router routes", () => {
  const analyzers = [new BrokenAccessControlAnalyzer()];

  it("flags an /admin route with no auth check and no middleware.ts nearby", () => {
    const source = `
      export async function GET() {
        return Response.json(await db.user.findMany());
      }
    `;
    const result = scanSource(source, "app/admin/users/route.ts", analyzers);
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]?.ruleId).toBe("broken-access-control");
  });

  it("flags a route inside an (admin) route group the same way (invisible in the real URL)", () => {
    const source = `
      export async function GET() {
        return Response.json(await db.user.findMany());
      }
    `;
    const result = scanSource(source, "app/(admin)/users/route.ts", analyzers);
    expect(result.findings).toHaveLength(1);
  });

  it("does not flag when the handler itself has an auth check", () => {
    const source = `
      export async function GET() {
        const session = await getServerSession(authOptions);
        if (!session?.user?.isAdmin) return new Response(null, { status: 403 });
        return Response.json(await db.user.findMany());
      }
    `;
    const result = scanSource(source, "app/admin/users/route.ts", analyzers);
    expect(result.findings).toHaveLength(0);
  });

  it("does not flag ordinary, non-privileged routes", () => {
    const source = `
      export async function GET() {
        return Response.json(await db.product.findMany());
      }
    `;
    const result = scanSource(source, "app/api/products/route.ts", analyzers);
    expect(result.findings).toHaveLength(0);
  });
});

describe("CsrfAnalyzer on Next.js App Router routes", () => {
  const analyzers = [new CsrfAnalyzer()];

  it("flags a POST route handler with no CSRF protection in the file", () => {
    const source = `
      export async function POST(request) {
        const body = await request.json();
        await db.transfer.create({ data: body });
        return Response.json({ ok: true });
      }
    `;
    const result = scanSource(source, "app/api/transfer/route.ts", analyzers);
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]?.ruleId).toBe("csrf");
  });

  it("does not flag GET route handlers", () => {
    const source = `
      export async function GET() {
        return Response.json(await db.transfer.findMany());
      }
    `;
    const result = scanSource(source, "app/api/transfer/route.ts", analyzers);
    expect(result.findings).toHaveLength(0);
  });
});
