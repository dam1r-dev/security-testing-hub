// Data-access layer: the SQL is built here, while the route handlers in app/api/orders*
// only forward request data. Imported through the `@/` alias, as in a real Next.js app.
import { db } from "./db";

// VULNERABLE: `status` is interpolated into the SQL text.
export function findOrders(status: string | null) {
  return db.prepare(`SELECT * FROM orders WHERE status = '${status}'`).all();
}

// Safe: bound parameter.
export function findOrdersSafe(status: string | null) {
  return db.prepare("SELECT * FROM orders WHERE status = ?").all(status);
}
