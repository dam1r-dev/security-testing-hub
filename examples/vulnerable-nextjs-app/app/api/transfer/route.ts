// VULNERABLE: Cross-Site Request Forgery (CWE-352) — state-changing route,
// no anti-forgery token check anywhere in this file. (Not writing the
// four-letter acronym here on purpose — see transfer.js in the Express
// fixture for why: the scanner's own heuristic treats that word appearing
// anywhere in the file as evidence the bug is already fixed.)
export async function POST(request: Request) {
  const body = await request.json();
  // ...move money using the authenticated session, no anti-forgery check...
  return Response.json({ status: "ok", amount: body.amount, to: body.to });
}
