import { db } from '$lib/db';

export const actions = {
  // changes data and never checks who is calling
  remove: async ({ request }) => {
    const data = await request.formData();
    await db.post.delete({ where: { id: data.get('id') } });
    return { success: true };
  },
  // checks the caller (locals.user) and scopes the query to them: fine
  rename: async ({ request, locals }) => {
    if (!locals.user) throw new Error('Unauthorized');
    const data = await request.formData();
    await db.post.update({ where: { id: data.get('id'), ownerId: locals.user.id }, data: { title: data.get('title') } });
    return { success: true };
  },
};
