// SAFE: parameterized query, should NOT be flagged.
import { db } from "../../../lib/db";

export async function GET(request: Request & { nextUrl: URL }) {
  const id = request.nextUrl.searchParams.get("id");
  const rows = db.prepare("SELECT * FROM users WHERE id = ?").all(id);
  return Response.json(rows);
}
