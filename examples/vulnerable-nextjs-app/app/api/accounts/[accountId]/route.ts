// VULNERABLE: IDOR (CWE-639) — no session/ownership check.
import { db } from "../../../../lib/db";

export async function GET(request: Request, { params }: { params: { accountId: string } }) {
  const account = await db.prepare("SELECT * FROM accounts WHERE id = ?").all(params.accountId);
  return Response.json(account);
}
