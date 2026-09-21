# Rule reference

Every rule except CSRF works the same way: **source → alias propagation →
sink**, scoped to a single function body (intra-procedural). See
[README.md](../README.md#scope--limitations) for why that scope was chosen.

## `sql-injection` (critical)

- **Sources:** `req.params`, `req.query`, `req.body`, `req.cookies`, `req.headers`
  (with or without a property/index access).
- **Sinks:** any call whose callee ends in `.query`, `.execute`, or `.raw`
  (covers `db.query`, `pool.execute`, `knex.raw`, `sequelize.query`, ...).
- **Not flagged:** calls whose first argument is a static string with no
  `${...}` interpolation and a second argument — the parameterized-query
  pattern (`db.query("... WHERE id = ?", [id])`).
- **Known gap:** doesn't verify the second argument is actually an
  array/object of bind params — a call shaped like `db.query("...")` with a
  static first arg is always treated as safe even if it takes no params at all.

## `xss` (high)

- **Sources:** same as above.
- **Sinks:** `res.send(...)`, `res.write(...)`, `res.end(...)` (object name
  must be `res` or `response`).
- **Not flagged:** `res.render(...)` — most template engines (EJS, Pug,
  Handlebars) auto-escape by default, so it's out of scope for this
  heuristic-level rule rather than a false negative.

## `command-injection` (critical)

- **Sources:** same as above.
- **Sinks:** `exec(...)`, `execSync(...)` (from `child_process`) — these run
  their string argument through a shell.
- **Not flagged:** `execFile`/`spawn` with an argv array — the shell never
  re-parses the string, so string-building into them isn't this bug class.

## `path-traversal` (high)

- **Sources:** same as above.
- **Sinks:** `fs.readFile`/`readFileSync`/`writeFile`/`writeFileSync`/
  `appendFile`/`appendFileSync`/`unlink`/`unlinkSync`/`createReadStream`/
  `createWriteStream`/`open`/`openSync` (object must be `fs`, `fsPromises`,
  or `promises`).
- **Confidence: low** — this rule can't currently see whether the path is
  later resolved and checked against a base directory before use, which is
  a common (and sufficient) mitigation. Expect a higher false-positive rate
  here than the other rules until that's added.

## `csrf` (medium) — heuristic, not taint-based

- Flags `app.post/put/delete/patch(...)` and `router.post/put/delete/patch(...)`
  registrations in any file that contains **no** occurrence of `/csrf/i`
  anywhere (covers `csurf`, `req.csrfToken()`, a custom `csrfProtection`
  middleware, etc.).
- **File-scoped, not route-scoped on purpose:** CSRF middleware is normally
  registered once per file with `app.use(...)`, not repeated per route, so
  per-route detection would just miss it and always fire.
- **False positives:** pure bearer-token/JWT APIs (not cookie-based) aren't
  exploitable via CSRF at all; this rule doesn't yet distinguish that and
  will still flag them. Session/cookie auth is the assumed case.

## Output formats

- `text` — colored terminal output.
- `json` — the full `ScanSummary` (see `packages/scanner/src/types.ts`).
- `sarif` — [SARIF 2.1.0](https://sarifweb.azurewebsites.net/), for GitHub
  code scanning and other SAST dashboards.
