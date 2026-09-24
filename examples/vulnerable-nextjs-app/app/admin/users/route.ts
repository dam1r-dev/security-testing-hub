// VULNERABLE: Broken Access Control (CWE-284/862) — no auth check, and this
// fixture app has no middleware.ts guarding it either.
import { db } from "../../../lib/db";

export async function GET() {
  const users = await db.prepare("SELECT * FROM users").all();
  return Response.json(users);
}
