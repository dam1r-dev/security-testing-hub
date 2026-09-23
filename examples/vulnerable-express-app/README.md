# Vulnerable Express App (test fixture)

A small, deliberately broken Express app used as ground truth for the scanner's
tests and as a quick manual demo. **Do not deploy this anywhere** — every route
is intentionally vulnerable.

| Route | Vulnerability |
|---|---|
| `GET /user/:id` | SQL Injection (string-interpolated query) |
| `GET /greet?name=` | Reflected XSS |
| `GET /user-safe/:id` | Safe (parameterized query) — should **not** be flagged |
| `POST /search` | SQL Injection via `knex.raw` |
| `GET /files/:name` | Path Traversal |
| `POST /ping` | OS Command Injection |
| `POST /transfer` | CSRF (no token check anywhere in the file) |
| `GET /api/accounts/:accountId` | IDOR (no ownership check) |
| `GET /api/accounts-safe/:accountId` | Safe (checks `account.ownerId === req.user.id`) — should **not** be flagged as IDOR |
| `GET /admin/delete-user` | Broken Access Control (no auth check) |
| `GET /dashboard` | Insecure Role Assignment (`req.cookies.Admin` trusted) |
| `POST /check-stock` | SSRF (`req.body.stockApi` fetched directly) |
| `POST /login` | Username Enumeration (distinct "invalid username" vs. "invalid password") |
| `upload.js` (`multer` config, no route) | Insecure File Upload (filter checks `file.mimetype` only) |

Run the scanner against it from the repo root:

```bash
npm run scan -- scan examples/vulnerable-express-app --format text
```
