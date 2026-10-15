import { db } from '../db';

export default defineEventHandler(async (event) => {
  const body = await readBody(event);
  const status = getQuery(event).status;
  await db.query("UPDATE orders SET status = '" + status + "' WHERE id = " + body.id);
  await db.order.create({ data: body });
  return { ok: true };
});
