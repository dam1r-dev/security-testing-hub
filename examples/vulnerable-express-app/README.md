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

Run the scanner against it from the repo root:

```bash
npm run scan -- scan examples/vulnerable-express-app --format text
```
