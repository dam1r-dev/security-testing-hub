// VULNERABLE: reflected XSS (CWE-79) via a raw Response body.
export async function GET(request: Request & { nextUrl: URL }) {
  const name = request.nextUrl.searchParams.get("name");
  return new Response(`<h1>Hello ${name}</h1>`, {
    headers: { "Content-Type": "text/html" },
  });
}
