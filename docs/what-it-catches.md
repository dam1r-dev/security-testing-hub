# What it catches: examples

Each block shows the mistake, what the scanner says, and the fix. The mistakes are the ones AI assistants write most often.
The full list of 29 rules, with what each one does not catch, is in [rules.md](rules.md). To see a rule on code that is
deliberately broken, run `npx security-hub scan examples/vulnerable-express-app` (or `vulnerable-nextjs-app`,
`vulnerable-supabase-app`, `vulnerable-firebase-app`, `vulnerable-frameworks`) in a clone of this repository.

## SQL injection (`sql-injection`, critical)

```js
app.get("/users", async (req, res) => {
  const rows = await db.query(`SELECT * FROM users WHERE name = '${req.query.name}'`);   // <- reported
  res.json(rows);
});
```

> User-controlled input ('req.query.name') flows into a SQL query without parameterization.

Fix (`security-hub fix` does this one): ``db.query("SELECT * FROM users WHERE name = $1", [req.query.name])``.
Also found when the query is built in another file, through a helper's return value, in a Next.js Server Action,
a SvelteKit `+server.ts`, a Remix `loader`, a Nuxt `defineEventHandler`, a tRPC `input` or a Hono `c.req.query()`, and in Prisma's
`$queryRawUnsafe`.

## Reflected XSS (`xss`, high)

```js
app.get("/hello", (req, res) => res.send(`<h1>Hello ${req.query.name}</h1>`));          // <- reported
```

Fix (automatic): ``${escapeHtml(req.query.name)}``.

## Broken access control and IDOR (`broken-access-control`, `idor`)

```ts
export async function deleteAccount(id: string) {          // "use server": anyone can call this directly
  "use server";
  await db.account.delete({ where: { id } });               // <- reported: changes data, never checks who is calling
}
```

```ts
removePost: publicProcedure.input(z.object({ id: z.string() })).mutation(({ ctx, input }) =>
  ctx.db.post.delete({ where: { id: input.id } }))          // <- reported: a public tRPC procedure
```

Fix: check the session first, and put the caller's id in the query: `where: { id, userId: user.id }`.

## Hard-coded secrets (`hardcoded-secret`, high / critical)

```js
const stripe = new Stripe("sk_live_..."); // a real key in the code: reported, never printed in full
app.use(session({ secret: "keyboard cat" }));
```

Fix (automatic): the value moves to `.env`, the code reads `process.env.STRIPE_SECRET_KEY`, `.env` goes into `.gitignore`;
the report reminds you to rotate the key, because it is already in your git history.

## Supabase without Row Level Security (`supabase-rls`, critical)

```sql
create table public.todos (id bigint primary key, owner uuid, title text);   -- <- reported: no RLS
```

Anyone with your public anon key can read and change every row. Fix (automatic migration): `alter table public.todos enable row
level security;` plus a policy such as `using (auth.uid() = owner)`.

## Firebase rules that are open (`firebase-rules`)

```
match /users/{uid} { allow read, write: if true; }           // <- reported
```

## Mass assignment (`mass-assignment`, medium)

```js
app.post("/signup", async (req, res) => res.json(await User.create(req.body)));   // <- reported
```

A caller can send `{"email": "...", "role": "admin"}`. Fix: `const { email, password } = req.body` and write only those.

## Payment webhook that believes anyone (`webhook-signature`, high)

```ts
export async function POST(request: Request) {
  const event = await request.json();
  if (event.type === "checkout.session.completed") await grantPlan(event);        // <- reported
}
```

The URL is public: anyone can post a forged event. Fix: `stripe.webhooks.constructEvent(rawBody, signature, secret)` first.

## Login token where scripts can read it (`insecure-token-storage`, medium)

```js
localStorage.setItem("token", response.token);                // <- reported
```

Fix: a server-set cookie with `HttpOnly; Secure; SameSite=Lax`.

## Open redirect (`open-redirect`, medium)

```js
app.get("/go", (req, res) => res.redirect(req.query.next));   // <- reported: /go?next=https://evil.com
```

Fix (automatic): `res.redirect(safeRedirect(req.query.next))`, where `safeRedirect` lets only a path on your own site through.

## Prototype pollution (`prototype-pollution`, high)

```js
_.merge(settings, req.body);      // <- reported: {"__proto__": {"isAdmin": true}} changes every object
```

## What it is not

A helper, not a replacement for a security review: rules are heuristics with known false positives and false negatives
([validation.md](validation.md) has the measured numbers, including the misses).
