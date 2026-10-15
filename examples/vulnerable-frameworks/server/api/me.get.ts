export default defineEventHandler(async (event) => {
  const session = await requireUserSession(event);
  return db.user.findUnique({ where: { id: session.user.id } });
});
