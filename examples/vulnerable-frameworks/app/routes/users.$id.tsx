import { db } from '~/db.server';

export async function loader({ params }) {
  return db.query(`SELECT * FROM users WHERE id = ${params.id}`);
}

// no session check before changing data
export async function action({ request, params }) {
  const form = await request.formData();
  await db.user.update({ where: { id: params.id }, data: { role: form.get('role') } });
  return null;
}
