// VULNERABLE: SQL Injection (CWE-89) across files. The query is built in lib/orders.ts.
import { findOrders } from "@/lib/orders";

export async function GET(request: Request) {
  const status = new URL(request.url).searchParams.get("status");
  return Response.json(findOrders(status));
}
