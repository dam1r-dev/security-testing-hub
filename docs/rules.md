# Rule reference

`sql-injection`, `xss`, `command-injection`, `path-traversal`, and `ssrf`
share one engine: **source → alias propagation → sink**, scoped to a single
function body (intra-procedural). See
[README.md](../README.md#scope--limitations) for why that scope was chosen.

The rest (`csrf`, `idor`, `broken-access-control`,
`insecure-role-assignment`, `insecure-file-upload`, `username-enumeration`)
are pattern/heuristic checks — they don't need a data-flow sink because the
bug is structural (a missing check, a trusted client value) rather than
"tainted data reached a dangerous call". See
[docs/attack-playbook.md](attack-playbook.md) for how to verify any of these
by hand, and for the two attack classes (2FA bypass, response-field
disclosure) that have no rule at all.

## Sources (shared by all five data-flow rules)

Defined once in `src/analyzers/sources.ts` so every rule stays in sync:

- **Express:** `req.params`, `req.query`, `req.body`, `req.cookies`, `req.headers`
  (with or without a property/index access), e.g. `req.params.id`.
- **Next.js App Router / Web Request API:** `request.nextUrl.searchParams.get(...)`,
  `new URL(request.url).searchParams.get(...)` (including the common
  `const { searchParams } = new URL(request.url)` destructured form),
  `request.cookies.get(...)`, and body readers `request.json()` / `.text()` / `.formData()`.
  Not yet covered: dynamic route segments (the `{ params }` second handler
  argument) — the name `params` is too generic to match safely without more
  context, so it's a known gap.

## `sql-injection` (critical)

- **Sinks:** any call whose callee ends in `.query`, `.execute`, `.raw`, or
  `.prepare` (covers `db.query`, `pool.execute`, `knex.raw`,
  `sequelize.query`, `db.prepare` as used by `better-sqlite3`/`node:sqlite`, ...).
- **Not flagged:** calls whose first argument is a static string with no
  `${...}` interpolation and a second argument — the parameterized-query
  pattern (`db.query("... WHERE id = ?", [id])`).
- **Known gap:** doesn't verify the second argument is actually an
  array/object of bind params — a call shaped like `db.query("...")` with a
  static first arg is always treated as safe even if it takes no params at all.

## `xss` (high)

- **Sinks:** `res.send(...)`, `res.write(...)`, `res.end(...)` (object name
  must be `res` or `response`).
- **Not flagged:** `res.render(...)` — most template engines (EJS, Pug,
  Handlebars) auto-escape by default, so it's out of scope for this
  heuristic-level rule rather than a false negative.

## `command-injection` (critical)

- **Sinks:** `exec(...)`, `execSync(...)` (from `child_process`) — these run
  their string argument through a shell.
- **Not flagged:** `execFile`/`spawn` with an argv array — the shell never
  re-parses the string, so string-building into them isn't this bug class.

## `path-traversal` (high)

- **Sinks:** `fs.readFile`/`readFileSync`/`writeFile`/`writeFileSync`/
  `appendFile`/`appendFileSync`/`unlink`/`unlinkSync`/`createReadStream`/
  `createWriteStream`/`open`/`openSync` (object must be `fs`, `fsPromises`,
  or `promises`).
- **Confidence: low** — this rule can't currently see whether the path is
  later resolved and checked against a base directory before use, which is
  a common (and sufficient) mitigation. Expect a higher false-positive rate
  here than the other rules until that's added.

## `csrf` (medium) — heuristic, not taint-based

- **Express:** flags `app.post/put/delete/patch(...)` and
  `router.post/put/delete/patch(...)` registrations in any file that
  contains **no** occurrence of `/csrf/i` anywhere (covers `csurf`,
  `req.csrfToken()`, a custom `csrfProtection` middleware, etc.).
- **Next.js App Router:** flags `export async function POST/PUT/DELETE/PATCH`
  handlers in a `route.ts` file under the same "no `/csrf/i` anywhere in the
  file" rule. Doesn't apply to Server Actions (`"use server"` functions) —
  those aren't `route.ts` files, and Next.js has protected them with an
  Origin-header check since v14, so they're a non-issue for this rule.
- **File-scoped, not route-scoped on purpose:** CSRF middleware is normally
  registered once per file (`app.use(...)` in Express), not repeated per
  route, so per-route detection would just miss it and always fire.
- **False positives:** pure bearer-token/JWT APIs (not cookie-based) aren't
  exploitable via CSRF at all; this rule doesn't yet distinguish that and
  will still flag them. Session/cookie auth is the assumed case.
- **Fixture-authoring gotcha (learned the hard way):** a comment describing
  *why* a route is vulnerable that happens to contain the word "CSRF"
  silently suppresses this rule on that exact file — the heuristic can't
  tell a real fix from a comment mentioning the bug by name. Both fixture
  apps' `transfer` routes hit this originally; see the comment in
  `examples/vulnerable-express-app/routes/transfer.js`.

## `ssrf` (high)

- **Sinks:** `fetch(url)`, `request(url)`, `got(url)`, and
  `axios`/`http`/`https` client methods (`.get`, `.post`, `.put`, `.delete`,
  `.patch`, `.head`, `.request`).
- **Known gap:** doesn't distinguish the URL argument from other arguments
  (e.g. request body/headers) — taint anywhere in the call's arguments is
  flagged, same simplification as the other taint rules.

## `idor` (high) — heuristic, route-scoped

- **Express:** flags `app`/`router` routes whose path has an id-like param
  (`:id`, `:userId`, `:accountId`, `:orderId`, ...) when the handler has
  **no** reference to `req.user`, `req.session`, `req.auth`, or
  `req.currentUser` anywhere in it.
- **Next.js App Router:** the id-like segment comes from the route's *file
  path* instead of a string (`app/api/accounts/[accountId]/route.ts`), so
  each exported `GET`/`POST`/`PUT`/`DELETE`/`PATCH` handler in the file is
  checked independently. A catch-all segment (`[...slug]`) is never treated
  as id-like — it's structurally a path, not a single record selector.
  Ownership-check evidence is broader than Express here too: NextAuth's
  `getServerSession`/`auth()`, Clerk's `currentUser()`, or any
  `session.user`/`session?.user` access, on top of the Express patterns.
- **Doesn't distinguish predictable vs. unpredictable (GUID) ids** — both
  get flagged identically, because the underlying bug (no per-object
  authorization check) is the same either way; an unguessable id only makes
  the attack slower to find manually, not impossible.
- **False positives:** routes that look up shared/public resources by id
  (e.g. `/api/products/:id`) don't need an ownership check and will still be
  flagged — this rule can't tell "belongs to a user" apart from "public data".

## `broken-access-control` (critical) — heuristic, route-scoped

- **Express:** flags `app`/`router` routes whose path looks privileged
  (`/admin`, `/internal`, `/manage`, `/management`, `/dashboard`, `/debug`,
  `/superuser`, `/root`) when the route registration has **no** reference to
  common auth/role-check identifiers (`isAuthenticated`, `requireAuth`,
  `requireAdmin`, `passport`, `req.user.role`, `jwt.verify`,
  `getServerSession`, `currentUser()`, `auth()`, ...).
- **Next.js App Router:** the "path" is the route's folder structure,
  including route groups like `(admin)` — invisible in the real URL, but
  still checked, since a `(admin)` group folder is a deliberate signal even
  though visitors never see it. Before flagging, this also walks up from the
  route file looking for a project-root `middleware.ts`/`.js` that mentions
  an auth-ish identifier, since Next.js commonly centralizes access control
  there via `config.matcher` instead of per-route. **This can't evaluate
  whether that middleware's matcher actually covers this specific route**
  (that needs implementing Next.js's matcher-pattern semantics, out of scope
  for v1) — so *any* auth-flavored middleware.ts in the project silences
  this rule everywhere, which trades away some true positives (a route the
  matcher doesn't actually cover) for far fewer false positives (the common
  case of a real, working middleware guard).
- **On purpose, a hidden/unguessable URL is flagged exactly the same as an
  obvious one** — the path being secret isn't access control.
- **False positives (Express):** a route whose auth check lives in a global
  `app.use(...)` middleware earlier in the file (rather than passed inline
  to this specific route, or named something this rule doesn't recognize)
  will still be flagged.

## `insecure-role-assignment` (critical) — pattern match, no sink

- Flags any read of a role/admin/permission-looking field directly from
  `req.body`/`req.query`/`req.cookies`/`req.headers`
  (`req.cookies.Admin`, `req.body.isAdmin`, `req.query.role`, ...).
- No taint-tracking needed here — the read itself is the bug, since the
  client fully controls that value regardless of where it's later used.
- **False positives:** legitimate uses like an admin-only *filter* parameter
  on a public search endpoint (`?role=admin` to filter a public directory,
  not to grant privileges) will still be flagged.

## `insecure-file-upload` (high)

- Flags a `multer({ fileFilter: ... })` whose filter function checks
  `file.mimetype` (client-supplied, from the `Content-Type` header) without
  also checking the file's extension/name (`file.originalname`,
  `path.extname`, ...).
- Only covers this specific, common bug shape; a `multer(...)` call with no
  `fileFilter` at all isn't flagged (broader risk, different fix).

## `username-enumeration` (medium) — heuristic, exact-wording only

- Within a function whose text mentions login/auth-ish keywords, flags two
  **distinct** string literals — one implying "no such user" (`invalid
  username`, `user not found`, ...) and another implying "wrong password"
  (`invalid password`, `incorrect password`, ...).
- **Narrow by design:** only catches differing message text. It cannot see
  differences in HTTP status code or response timing, which are just as
  exploitable for enumeration — those need manual/dynamic testing (see
  [docs/attack-playbook.md](attack-playbook.md)).

## Not covered by static analysis (see the manual testing guide instead)

Two classes from the same attack list this scanner targets aren't reliably
catchable by parsing source code, and there's no rule for them:

- **2FA bypass by URL/state manipulation** — whether a "2FA verified" flag is
  actually enforced on every protected route is a property of runtime
  session state and request flow, not something visible in a single file's
  AST.
- **IDOR variants that leak a password field in a response** — this scanner
  doesn't model response JSON shapes, so it can't tell a leaked password
  field from any other field. The `idor` rule above still catches the root
  cause (missing ownership check) for the same routes.

Both are covered as manual checklist items in
[docs/attack-playbook.md](attack-playbook.md).

## Output formats

- `text` — colored terminal output, ending with a colored score line.
- `json` — the full `ScanSummary` plus a `score` field (see
  `packages/scanner/src/types.ts` and `output/score.ts`).
- `sarif` — [SARIF 2.1.0](https://sarifweb.azurewebsites.net/), for GitHub
  code scanning and other SAST dashboards.
- `html` — a self-contained report file (no server, no external assets) with
  the score as a colored ring, a severity breakdown, and a filterable
  findings list. Always writes to a file (`security-report.html` by default,
  or `--out <path>`) since raw HTML isn't useful printed to a terminal.

## The 0-100 score

Every format carries a score: `100 - Σ(severity weight × confidence
multiplier)` over all findings, clamped to `[0, 100]`.

| Severity | Weight | | Confidence | Multiplier |
|---|---|---|---|---|
| critical | 20 | | high | 1.0 |
| high | 10 | | medium | 0.7 |
| medium | 4 | | low | 0.4 |
| low | 1 | | | |

Confidence weighting exists because our own heuristic rules
(csrf/idor/broken-access-control/...) self-report `confidence: "low"` — a
route-shape guess shouldn't cost the score as much as a taint-tracked SQL
injection at `confidence: "high"`. Bands: green ≥80, yellow 50-79, red <50.

This is deliberately simple and auditable (linear, no hidden curve) rather
than tuned to produce a "nice" distribution — treat it as a rough signal for
tracking whether a codebase is trending better or worse over time, not a
score to optimize for its own sake or compare across unrelated projects
(a project with 3 files and one critical finding scores the same as one
with 300 files and one critical finding).
