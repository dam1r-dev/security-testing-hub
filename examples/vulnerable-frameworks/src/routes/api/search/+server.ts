import { json } from '@sveltejs/kit';
import { db } from '$lib/db';

// SQL injection: the query string goes straight into the statement
export async function GET({ url }) {
  const q = url.searchParams.get('q');
  const rows = await db.query(`SELECT * FROM products WHERE name LIKE '%${q}%'`);
  return json(rows);
}

// SQL injection through the route parameter (destructured on its own)
export async function DELETE({ params }) {
  await db.query('DELETE FROM posts WHERE id = ' + params.id);
  return json({ ok: true });
}

// safe: parameterised
export async function PUT({ params, request }) {
  const body = await request.json();
  await db.query('UPDATE posts SET title = $1 WHERE id = $2', [body.title, params.id]);
  return json({ ok: true });
}
