import { json } from '@sveltejs/kit';
import { prisma } from '$lib/db';

// mass assignment: the caller can add `role: "admin"` to the body
export async function PATCH({ request, locals }) {
  if (!locals.user) return json({ error: 'sign in' }, { status: 401 });
  const body = await request.json();
  const updated = await prisma.user.update({ where: { id: locals.user.id }, data: body });
  return json(updated);
}
