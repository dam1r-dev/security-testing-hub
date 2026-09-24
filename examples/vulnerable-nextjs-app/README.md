# Vulnerable Next.js App Router App (test fixture)

Same idea as [`examples/vulnerable-express-app`](../vulnerable-express-app),
but in Next.js App Router style (`route.ts` handlers, `NextRequest`/`Request`,
`request.nextUrl.searchParams`, `request.cookies.get(...)`, `request.json()`)
— proving the scanner isn't Express-only. **Do not deploy this.**

| Route | Vulnerability |
|---|---|
| `GET /api/search?category=` | SQL Injection via `request.nextUrl.searchParams` |
| `GET /api/user-safe?id=` | Safe (parameterized query) — should **not** be flagged |
| `GET /api/proxy` | SSRF via a client-controlled cookie |
| `GET /api/greet?name=` | Reflected XSS via a raw `Response` body |
| `POST /api/ping` | OS Command Injection via a JSON request body |
| `POST /api/transfer` | CSRF (no anti-forgery token check anywhere in the file) |
| `GET /api/accounts/[accountId]` | IDOR (id-like dynamic segment, no session/ownership check) |
| `GET /api/accounts-safe/[accountId]` | Safe (checks `account.ownerId === session.user.id`) — should **not** be flagged as IDOR |
| `GET /admin/users` | Broken Access Control (no auth check, no `middleware.ts` guarding it) |

Run the scanner against it from the repo root:

```bash
npm run scan -- scan examples/vulnerable-nextjs-app --format text
```
