import { scanSource } from "../src/index";
import { SqlInjectionAnalyzer } from "../src/analyzers/sql-injection";
import { SsrfAnalyzer } from "../src/analyzers/ssrf";
import { XssAnalyzer } from "../src/analyzers/xss";
import { CommandInjectionAnalyzer } from "../src/analyzers/command-injection";

describe("Next.js App Router request sources", () => {
  it("flags SQL injection from request.nextUrl.searchParams.get(...)", () => {
    const source = `
      export async function GET(request) {
        const category = request.nextUrl.searchParams.get("category");
        const rows = db.prepare(\`SELECT * FROM products WHERE category = '\${category}'\`).all();
        return Response.json(rows);
      }
    `;
    const result = scanSource(source, "route.ts", [new SqlInjectionAnalyzer()]);
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]?.ruleId).toBe("sql-injection");
  });

  it("flags SQL injection from new URL(request.url).searchParams.get(...)", () => {
    const source = `
      export async function GET(request) {
        const { searchParams } = new URL(request.url);
        const id = searchParams.get("id");
        const rows = db.prepare(\`SELECT * FROM users WHERE id = \${id}\`).all();
        return Response.json(rows);
      }
    `;
    const result = scanSource(source, "route.ts", [new SqlInjectionAnalyzer()]);
    expect(result.findings).toHaveLength(1);
  });

  it("flags command injection from a JSON request body (request.json())", () => {
    const source = `
      export async function POST(request) {
        const body = await request.json();
        const host = body.host;
        exec(\`ping -c 1 \${host}\`);
      }
    `;
    const result = scanSource(source, "route.ts", [new CommandInjectionAnalyzer()]);
    expect(result.findings).toHaveLength(1);
  });

  it("flags SSRF from a Next.js cookie value", () => {
    const source = `
      export async function GET(request) {
        const target = request.cookies.get("redirectTo")?.value;
        const res = await fetch(target);
        return new Response(await res.text());
      }
    `;
    const result = scanSource(source, "route.ts", [new SsrfAnalyzer()]);
    expect(result.findings).toHaveLength(1);
  });

  it("flags reflected XSS into a raw Response body", () => {
    const source = `
      export async function GET(request) {
        const name = request.nextUrl.searchParams.get("name");
        return new Response(\`<h1>Hello \${name}</h1>\`, { headers: { "Content-Type": "text/html" } });
      }
    `;
    const result = scanSource(source, "route.ts", [new XssAnalyzer()]);
    expect(result.findings).toHaveLength(1);
  });

  it("does not flag NextResponse.json(...) as an XSS sink (it's a safe JSON response, not a source)", () => {
    const source = `
      export async function GET(request) {
        const name = request.nextUrl.searchParams.get("name");
        return NextResponse.json({ greeting: \`Hello \${name}\` });
      }
    `;
    const result = scanSource(source, "route.ts", [new XssAnalyzer()]);
    expect(result.findings).toHaveLength(0);
  });

  it("does not flag a static, hardcoded fetch URL", () => {
    const source = `
      export async function GET() {
        const res = await fetch("https://api.example.com/health");
        return new Response(await res.text());
      }
    `;
    const result = scanSource(source, "route.ts", [new SsrfAnalyzer()]);
    expect(result.findings).toHaveLength(0);
  });
});
