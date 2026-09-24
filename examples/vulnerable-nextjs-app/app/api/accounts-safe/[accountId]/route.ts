// SAFE: session/ownership check present — should NOT be flagged as IDOR.
import { db } from "../../../../lib/db";
import { getServerSession } from "../../../../lib/auth";

export async function GET(request: Request, { params }: { params: { accountId: string } }) {
  const session = await getServerSession();
  const [account] = await db.prepare("SELECT * FROM accounts WHERE id = ?").all(params.accountId);
  if (!account || account.ownerId !== session.user.id) {
    return new Response(null, { status: 403 });
  }
  return Response.json(account);
}
