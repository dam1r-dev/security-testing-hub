import { Hono } from 'hono';
const app = new Hono();

app.get('/search', async (c) => {
  const term = c.req.query('term');
  const rows = await db.query(`SELECT * FROM items WHERE name = '${term}'`);
  return c.json(rows);
});
app.get('/file', async (c) => {
  const name = c.req.param('name');
  return c.body(await fs.readFile('./uploads/' + name));
});
export default app;
