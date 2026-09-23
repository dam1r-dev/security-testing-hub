// VULNERABLE: SQL Injection (CWE-89) via request.nextUrl.searchParams.
import { db } from "../../../lib/db";

export async function GET(request: Request & { nextUrl: URL }) {
  const category = request.nextUrl.searchParams.get("category");
  const rows = db.prepare(`SELECT * FROM products WHERE category = '${category}'`).all();
  return Response.json(rows);
}
