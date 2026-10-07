// Safe: lib/orders.ts binds the value as a parameter — should NOT be flagged.
import { findOrdersSafe } from "@/lib/orders";

export async function GET(request: Request) {
  const status = new URL(request.url).searchParams.get("status");
  return Response.json(findOrdersSafe(status));
}
