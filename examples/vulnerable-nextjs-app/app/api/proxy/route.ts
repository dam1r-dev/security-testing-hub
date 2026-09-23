// VULNERABLE: SSRF (CWE-918) via a client-controlled cookie fetched server-side.
export async function GET(request: Request & { cookies: { get(name: string): { value: string } | undefined } }) {
  const target = request.cookies.get("redirectTo")?.value;
  const upstream = await fetch(target as string);
  return new Response(await upstream.text());
}
