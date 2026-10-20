# Rule reference

`sql-injection`, `xss`, `command-injection`, `path-traversal`, `ssrf`,
`code-injection`, `open-redirect`, `insecure-deserialization` and `xxe`
share one engine: **source → alias propagation → sink**. Inside a function
the engine follows local variables, destructuring and template strings; across
functions it uses *summaries* (see below). See
[README.md](../README.md#scope--limitations) for what is and isn't followed.

## Hiding findings

`// security-hub-ignore [rule-id, ...] [-- reason]` on the flagged line or the line directly above hides
it (all rules if none are named); a `.security-hub-ignore` file or `--ignore <pattern>` skips whole paths;
`--include-tests` scans test folders. Hidden findings are counted in the report (`suppressedCount` in the
JSON output), never dropped silently. See the README for the pattern syntax.

## What counts as a dangerous argument, and what cleans a value

A sink only fires through the argument that matters: the query **text** of `db.query(sql, values)`, the
**path** of `fs.writeFile(path, data)`, the **target** of `redirect(url, { headers })`, the **URL** of `fetch(url,
options)`. A tainted value in the bound parameters, the file content or a header is not an injection through that
sink. A value that went through a **cleaning call** is no longer tainted: numeric coercion (`parseInt`, `Number`),
hashing (`hash*`, `md5`, `sha*`), escaping / sanitising (`escape*`, `sanitize*`, `encodeURIComponent`, `quote*`).
`String(x)` and `x.toString()` change nothing and are not on the list. A value picked from a **list after a
membership check** (`ALLOWED.includes(x) ? x : "jpg"`) is treated as validated, and so is one **looked up by a
user-chosen key** (`TABLE[req.query.name]`).

## How data is followed across functions and files

For every project function, per rule, the engine works out **which parameters
reach a dangerous call** — directly, or by being passed on to another function
that does (up to six calls deep; recursion is cut off). At each call site that
passes request data into such a parameter, the finding is reported **at the call
site**, where the user input is visible, and its message says where the dangerous
call is:

```text
routes/users.js:8   User-controlled input ('req.query.owner') flows into a SQL query ...
                    The value is passed to findByOwner() and reaches the vulnerable call at
                    services/report-service.js:8.
```

How a call is resolved to a function (name-based, no type checker):

| Form | Example |
|---|---|
| Same-file function | `find(req.query.q)` |
| CommonJS | `const svc = require("./svc"); svc.find(x)`, `const { find } = require("./svc")`, `exports.f = ...`, `module.exports = { f }` / `= function` / `= Class` |
| ES modules | `import { f }`, `import f`, `import * as ns`, `export default`, barrel files (`export * from`, `export { x } from`) |
| Path aliases | `@/…`, `~/…`, and `compilerOptions.paths` / `baseUrl` from `tsconfig.json` / `jsconfig.json` |
| Objects & classes | `const dao = { find() {} }`, `new Service().find(x)`, `this.helper(x)`, `extends`, constructor functions with `this.find = function`, `Ctor.prototype.find = ...` |

Only the **dangerous argument** counts: for `query(sql, params)` only `sql` is a
sink slot, so `query("... WHERE id = ?", [req.params.id])` stays clean. A value
wrapped in a call (`parseInt(x)`, `escape(x)`) or used only as a table key
(`CONFIG[req.query.name]`) is not treated as tainted.

**Values that come back out of a function** are followed too, with the same precision rule:

```js
function buildQuery(name) { return "SELECT * FROM users WHERE name = '" + name + "'"; }
const q = buildQuery(req.query.name);   // q carries the input
db.query(q);                             // reported

function getId(req) { return req.params.id; }   // a call that RETURNS request input is a source
db.query("... WHERE id = " + getId(req));        // reported
```

A parameter counts as returned only when it is used **directly** in the returned expression (concatenation, a template
literal, the bare name, a ternary branch). Passing it through another call (`return escape(name)`,
`return parseInt(id)`) is a cleaning step the engine cannot see into, so it contributes nothing. A helper is never
followed when its own name says it cleans or checks (`sanitize*`, `escape*`, `validate*`, `safe*`, `verify*`, `check*`,
`toInt`, `hash*`, ...), or when it tests the value before returning it (`if (!ALLOWED.includes(v)) return "a";`,
`return next.startsWith("/") ? next : "/"`). What a condition decides is not part of the value either:
`token ? table[token] : undefined`, `a === b` and `!x` do not carry `token`. A helper wrapped in `asyncHandler(...)`,
`catchAsync(...)`, `cache(...)` or `memoize(...)` resolves to the wrapped function.

**Not followed** (reported as a limitation, never guessed): callbacks, values stored in object fields,
dependency-injection containers, dynamic `require(variable)`, factory functions that return objects,
and calls on objects whose class can't be determined by name.

### Next.js Server Actions

A function in a file that starts with `"use server"` (every exported async function in it) or with `"use server"` as the
first statement of its body is a Server Action: a **public POST endpoint** whose arguments (`formData`, an id,
`prevState`) come from the browser. They are request input for every data-flow rule above, so
`db.query("... '" + name + "'")` inside an action is reported like it would be in a route handler. Two heuristic checks
are specific to actions:

- `broken-access-control` (high, medium confidence): an action that changes data (`prisma.x.create/update/delete`,
  `db.x.insert`, `.from("t").insert/update/delete`, `setDoc`, ...) and never checks who is calling: no `auth()`,
  `getUser()`, `getServerSession()`, `currentUser()`, `requireUser()`-style call in it or in a helper it calls (two
  levels deep, across files), no session cookie read. Not reported for actions named like `login`, `signUp`,
  `contact`, `subscribe`, `resetPassword` (they run before sign-in), for non-mutating actions, or when every change goes
  through a Supabase client built from the request's cookies: Row Level Security is the check there and the
  `supabase-rls` rule reads the policies. A service-role / admin client does not get that exemption.
- `idor` (high, low confidence): the action checks that someone is signed in, then changes the record whose id the
  browser sent (an `id` / `xId` parameter or `formData.get("todoId")`) with no sign that the record belongs to the
  caller: no `userId` in a query filter, no comparison with the caller's id, no `verify…Ownership()` helper.

The rest (`csrf`, `idor`, `broken-access-control`,
`insecure-role-assignment`, `insecure-file-upload`, `username-enumeration`)
are pattern/heuristic checks — they don't need a data-flow sink because the
bug is structural (a missing check, a trusted client value) rather than
"tainted data reached a dangerous call". See
[docs/attack-playbook.md](attack-playbook.md) for how to verify any of these
by hand, and for the two attack classes (2FA bypass, response-field
disclosure) that have no rule at all.

## What gets scanned

`scanPath` skips: `node_modules`, `.git`, `dist`, `build`, `coverage`, `.next`,
`generated` / `__generated__` (machine-written code), `vendor` / `vendors`
(bundled libraries), test directories (`test`, `tests`, `__tests__`,
`__mocks__`, `e2e`, `cypress`), and `*.test.*`, `*.spec.*`, `*.min.js` files.
Test code was the biggest false-positive source on real projects — see
[validation.md](validation.md). Pass a single test file path explicitly to
scan it anyway.

Besides source files, `.env*` files (not templates like `.env.example`) are checked for committed secrets
— see [`hardcoded-secret`](#hardcoded-secret-high--critical--pattern-match-no-sink).

## Sources (shared by all five data-flow rules)

Defined once in `src/analyzers/sources.ts` so every rule stays in sync:

- **Express / Fastify:** `req.params`, `req.query`, `req.body`, `req.cookies`, `req.headers`, `req.file(s)`
  (also spelled `request.…`), with or without a property/index access, e.g. `req.params.id`.
- **Koa:** `ctx.query`, `ctx.params`, `ctx.request.body`, `ctx.headers`, `ctx.cookies`, ...
- **Hono:** `c.req.param()`, `c.req.query()`, `c.req.json()`, `c.req.parseBody()`, `c.req.header()`, ...
- **Destructured handler parameters:** `async ({ body, file }: Request, res) => ...` and Remix's
  `({ request, params })` bind names that carry request data from the first line. A first parameter is treated
  as a request only when its type mentions `Request` / `Args` or a `res` / `response` / `reply` parameter follows,
  so an ordinary `function Card({ body })` is not.
- **Next.js App Router / Web Request API:** `request.nextUrl.searchParams.get(...)`,
  `new URL(request.url).searchParams.get(...)` (including the common
  `const { searchParams } = new URL(request.url)` destructured form),
  `request.cookies.get(...)`, and body readers `request.json()` / `.text()` / `.formData()`.
  Dynamic route segments arrive as the second handler argument, `GET(request, { params })`
  (also `await params` in Next 15, and `context.params.id`).

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
- **When it does not apply (and stays quiet):** CSRF needs a credential the browser attaches by itself,
  so the rule is skipped for (a) pure bearer-token/JWT APIs, (b) projects whose only session mechanism is a
  framework whose cookie is `SameSite=Lax` by default (Auth.js/NextAuth, Clerk, Supabase SSR, Better Auth,
  iron-session, Lucia) — a cross-site POST arrives without the cookie, and (c) projects whose `package.json`
  shows no authentication library at all (demos, public APIs). It also skips webhook / on-demand-revalidation
  endpoints and routes switched off by a `denyAll()`-style middleware. Cookie/session middleware the app
  configures itself (`express-session`, `cookie-parser`, `cookie-session`, ...) keeps the rule on. Measured
  effect: 25 of 25 CSRF findings on modern Next.js projects in the second validation round were noise.
  It also reads the project's own code: a `csrf`/`xsrf` mention in ANY source file (the middleware is usually
  registered once in an entry file, the routes live elsewhere) switches the rule off for the project, and so does an
  app that reads the `Authorization` header and never touches `req.cookies` / `req.session` (a session library that
  is installed but unused does not count). Apps whose only auth is the Firebase or Supabase client keep the user's
  token in the page, not in a cookie, and are skipped too.
- **Fixture-authoring gotcha (learned the hard way):** a comment describing
  *why* a route is vulnerable that happens to contain the word "CSRF"
  silently suppresses this rule on that exact file — the heuristic can't
  tell a real fix from a comment mentioning the bug by name. Both fixture
  apps' `transfer` routes hit this originally; see the comment in
  `examples/vulnerable-express-app/routes/transfer.js`.

Path traversal sinks cover the `fs` read/write/delete/list calls (`readFile`, `writeFile`, `createReadStream`,
`readdir`, `stat`, `rm`, `rename`, `copyFile`, `mkdir`, ...) and the file-serving calls `res.sendFile()` and
`res.download()`.

## `insecure-cors` (high) — pattern match

CORS that lets **any website** read what a logged-in user's browser fetches from your server. Browsers send cookies to
another origin only when the response says `Access-Control-Allow-Credentials: true` **and** names that origin. A server
that accepts every origin together with credentials turns every page a user visits into a client of their session:
it can call your API as them and read the answers.

Reported (high): `cors({ origin: true, credentials: true })`, an `origin` callback that tests nothing
(`(origin, cb) => cb(null, true)`), a catch-all regex (`/.*/`), `@fastify/cors` registered the same way, and headers
written by hand (`res.setHeader("Access-Control-Allow-Origin", req.headers.origin)` next to
`Access-Control-Allow-Credentials: true`, also as an object of headers in a Next.js `Response`).

Not reported: a named origin or a list, a callback that checks the origin against something, `origin: "*"` (browsers
refuse to combine it with credentials), and any permissive origin **without** credentials (the response carries
nothing personal). Wildcard CORS on a public API is a design choice, not a finding.

## `insecure-jwt` (critical / high / medium) — pattern match

Covers `jsonwebtoken` (including `import jwt`, `const { sign } = require(...)` and other aliases) and `jose`'s
`SignJWT`. Client components (`"use client"`) are skipped.

| Finding | Severity |
|---|---|
| `verify(..., { algorithms: [..., "none"] })` or `sign(..., { algorithm: "none" })`: tokens with no signature are accepted or issued | critical |
| `verify(..., { ignoreExpiration: true })`: a token that leaked once works for ever | high |
| `jwt.decode(x)` where `x` comes from the request (a header, a cookie, a body field, a `token` parameter) in a file that never calls `verify`: `decode` only reads the payload, anyone can write one | high |
| `jwt.sign({ ... }, secret)` with no `exp` in the payload and no `expiresIn` in the options; `new SignJWT(...)...sign(key)` with no `setExpirationTime` | medium |

The no-expiry check only fires when the payload and the options are written out in the call (a payload held in a
variable, a spread, or options in a variable are unknown, so they are skipped). `decode` of a token the **server**
holds (`decode(tokens.get(userId))`) is not reported. Weak and hard-coded signing secrets are `hardcoded-secret`'s job.

## `missing-rate-limit` (medium) — heuristic, project-scoped

A login or one-time-code endpoint that anyone can call as fast as they like: passwords and 6-digit codes are guessed by
scripts. Reported only when the app **checks the credential itself** (`bcrypt.compare`, `argon2.verify`, `compareSync`,
`comparePassword`, a TOTP check, a code compared with `===`, `timingSafeEqual`) in a route whose path looks like sign-in or
a code check (`/login`, `/signin`, `/auth`, `/session`, `/token`, `/otp`, `/2fa`, `/verify-code`, ...), in an Express route (the
handler is followed into its controller), a Next.js `route.ts`, a Server Action named like `login`, or an Auth.js
`Credentials({ authorize })` provider. Hosted sign-in (Auth.js OAuth providers, Clerk, Supabase Auth, Firebase Auth) is
rate limited by the provider and is not reported.

It stays quiet when the project shows rate limiting **anywhere**: a limiter package in `package.json`
(`express-rate-limit`, `rate-limiter-flexible`, `@upstash/ratelimit`, `@nestjs/throttler`, ...), or `rateLimit` / `limiter` /
`throttle` / `lockout` / `failedAttempts` / `status(429)` in any source file. One finding per file. A limit applied by a
gateway or CDN is invisible to a static scan: add `// security-hub-ignore missing-rate-limit` above the endpoint.

## `exposed-files` (critical / high) — file system, not source code

Files that must never be reachable from the internet but sit in a folder the web server hands out. Everything in
`public/` (Next.js, Vite, CRA, Nuxt, Astro, Gatsby, SvelteKit), `static/`, `www/`, `wwwroot/` and in any folder passed to
`express.static()` is served to every visitor as it is, at the same path.

| Found in a served folder | Severity |
|---|---|
| `.env` with values (not `.env.example` / `.sample` / `.template`), a private key (`*.pem` containing `PRIVATE KEY`, `id_rsa`, `.p12`, `.pfx`, `.jks`), a service-account file (`private_key` inside) | critical |
| A `.git` / `.svn` / `.hg` folder: the whole source code and every secret ever committed | critical |
| `express.static(".")` / `express.static(__dirname)` / `path.join(__dirname, "..")` that resolves to the project folder: `/.env`, `/package.json` and every source file can be downloaded | critical |
| A database file (`.sqlite`, `.db`), an SQL dump, a backup (`backup*.zip`, `dump*.gz`, `*.bak`), a credentials file (`credentials.json`, `.htpasswd`, `.npmrc` with a token) | high |

Never prints a secret: the message names the file and the URL it can be downloaded at. A file that git ignores is
skipped (Vercel, Netlify and GitHub Pages deploy from the repository, so an ignored file is not part of the deploy);
a `.git` folder is always reported. Confidence is high when `package.json` shows a framework that serves `public/`.

## `vulnerable-dependency` (critical / high / medium / low) — optional, `scan --audit`

Known vulnerabilities in the packages your project depends on, from npm's advisory database. This is **the only feature
that uses the network**: `npm audit` sends the names and versions of your dependencies to the npm registry, so it runs
**only** when you pass `--audit`, never installs anything, and needs a `package-lock.json` (create one without installing:
`npm install --package-lock-only`). Without the flag the scan stays fully offline.

One finding per vulnerable **direct** dependency, placed on its line in `package.json`: the installed version, up to three
advisory titles, a link, and the fix (`npm install pkg@fixed`, marked when it is a major upgrade). The vulnerable packages
your dependencies pull in (transitive) are summed up in one finding with the worst severity, because listing hundreds of
them would bury the ones you can act on. npm's `moderate` is reported as `medium`. If npm cannot run (offline, no lock
file) you get a warning, never a clean bill of health. Not covered: advisories npm does not know, vulnerable code that
is vendored into your repository, and packages installed outside `package.json`.

## Other frameworks: SvelteKit, Remix, Nuxt, tRPC, Hono

The data-flow rules start from "where does request data come from", and that differs per framework. All of these count as request input
for every data-flow rule (SQL injection, XSS, command injection, path traversal, SSRF, code injection, open redirect, ...):

| Framework | Request input |
|---|---|
| SvelteKit | `url.searchParams.get(...)`, `await request.json()` / `request.formData()`, `event.params.x`, and `params` destructured from the first argument of an exported `GET` / `POST` / `load` / form `actions` function |
| Remix / React Router | `params` and `request` of an exported `loader` / `action`, `new URL(request.url).searchParams.get(...)`, `await request.formData()` |
| Nuxt / Nitro (h3) | `getQuery(event)`, `readBody(event)`, `getRouterParam(event, "id")`, `getHeader(event, ...)`, `getCookie(event, ...)`, `readFormData(event)` |
| tRPC | `input` of a `.query(...)` / `.mutation(...)` resolver ({ input } or `opts.input`). It is the caller's even though a schema validated it: a validated string is still a string that can carry SQL. It is not used by the NoSQL rule (a schema-typed value cannot be an operator object) |
| Hono | `c.req.query()`, `c.req.param()`, `c.req.json()`, `c.req.header()`, `c.req.valid()` |

`request.headers.get(...)` of the incoming request is input in all of them (the headers of a `fetch` response are not).

**Access control** for the handlers of these frameworks reuses the two rules of the Server Actions section:

- `broken-access-control` (high): a handler that changes data and never checks who is calling. Handlers looked at: SvelteKit `+server`
  `POST`/`PUT`/`PATCH`/`DELETE` and form `actions`; a Remix `action`; a Nuxt `defineEventHandler` under `server/api` or `server/routes`;
  a tRPC `.mutation(...)` on a `publicProcedure` (a `protectedProcedure` is taken as checked by its name; a procedure with `.use(...)` is
  not judged).
- `idor` (high, low confidence): the caller is checked, but the record named by an id from the request is changed without the caller's id
  in the query or a comparison.

What counts as "checks the caller": `locals.user` / `locals.session`, `ctx.session` / `ctx.user`, `requireUserSession`, `getServerSession`,
`requireUserId`, `authenticator.isAuthenticated`, a 401 / redirect to a login page, any of the helpers named in the Server Actions section,
or a SvelteKit `hooks.server.ts` / Nuxt `server/middleware` file that stops anonymous requests for the whole project. Public-on-purpose
names (login, signup, contact, webhook, newsletter, ...) and Supabase calls through the caller's own cookie-bound client (Row Level Security
decides) are left alone. Role gates (`role === "admin"`) are not an ownership question and are not reported as `idor`.

**Prisma:** `prisma.$queryRawUnsafe(...)` and `$executeRawUnsafe(...)` are SQL sinks. `$queryRaw` / `$executeRaw` as a tagged template
(`$queryRaw\`... ${id}\``) bind their values and are not reported; called with a string built by hand they are.

## `mass-assignment` (medium) — pattern match

The WHOLE request body (`req.body`, `await request.json()`, `readBody(event)`, a variable holding one, `{ ...body }`, `Object.fromEntries(formData)`)
is passed to a database write: `Model.create(...)`, `prisma.x.update({ data: body })`, `new Model(body)`, `Object.assign(record, body)`,
`.findByIdAndUpdate(id, body)`, `supabase.from(...).update(body)`, Drizzle `.values(body)`. Anything the caller adds is written too:
`role: "admin"`, `isAdmin`, `balance`, `price`, `ownerId`, `emailVerified`.

- Not reported: picked fields (`const { name, email } = req.body`), a value that went through `schema.parse` / `.validate` / `pick` / `omit`,
  a function that `delete`s fields from the body first, a body used only in a `where` filter.
- Medium because it is only a hole when the model has a field the caller must not set, which the scanner cannot see.

## `prototype-pollution` (high) — taint-based

Request data reaches a deep merge (`_.merge`, `_.defaultsDeep`, `_.set` with a request-controlled path, `deepmerge(...)`, `$.extend(true, ...)`)
or is the key of a nested assignment (`target[req.body.a][req.body.b] = v`). A body of `{"__proto__": {"isAdmin": true}}` then adds `isAdmin` to
every object in the process.

- A bare `merge(...)` counts only when the file imports lodash / deepmerge / a similar library: a project's own `merge` helper is not flagged.
- `Object.assign` and spread are shallow and cannot pollute (they belong to `mass-assignment`).
- Also found through helpers in other files, like every data-flow rule.

## `webhook-signature` (high) — pattern match

A handler that acts on a payment provider's event names (Stripe `checkout.session.completed`, `payment_intent.succeeded`, `invoice.paid`,
`customer.subscription.*`; Lemon Squeezy `order_created`, `subscription_created`; Paddle `transaction.completed`) and shows no sign of verifying
the caller: no `constructEvent`, signature header, `svix`, HMAC / `timingSafeEqual` or a function with "verify" in its name (which may live in
another file). The URL of a webhook is public; without the check anyone can post `checkout.session.completed` and get a paid plan for free.
Comments are ignored (a "TODO: check the signature" is not a check); a file that only lists event names, with no handler in it, is not reported.

## `insecure-token-storage` (medium) — pattern match

A credential kept where any script can read it: `localStorage.setItem("token", ...)` (also `sessionStorage`, `localStorage.token = ...`,
`localStorage["jwt"] = ...`), `document.cookie = "token=..."` and `Cookies.set("token", ...)` (a cookie written from JavaScript cannot be HttpOnly).
Keys count when they name a credential (`token`, `jwt`, `bearer`, `secret`, `session_id`, `api_key`, `password`). UI state (`theme`, `authMode`), CSRF
tokens and flags (`hasToken`) do not. The fix is a server-set cookie with `HttpOnly`, `Secure` and `SameSite`.

## Python and PHP

Python (`.py`: Flask, FastAPI, Django) and PHP (`.php`: plain scripts, Laravel, Symfony) are read by their own analyzers (`packages/scanner/src/python`,
`.../php`) and reported under the same rule ids, so `security-hub-ignore`, `.security-hub.json`, the baseline and the score work as for JavaScript.
The tree-sitter grammars are **optional packages**: when one is missing the files are listed with a note, never skipped silently.

**How data is followed.** One function at a time (the top level of a PHP script is a scope too), statements in the order they run: a variable
that is assigned something built from request data holds request data from then on; assigned something clean, it does not. What carries a value
on: f-strings, `+` / `.` / `%`, `.format()`, `.join()`, string methods, subscripts and attributes of a tainted object, `str()`, `sprintf`, `trim`...
What stops it: a call that cleans (Python `int()`, `escape()`, `quote()`, `secure_filename()`; PHP `(int)`, `intval`, `htmlspecialchars`, `escapeshellarg`,
`mysqli_real_escape_string`, `basename`...) and a bound parameter (`cursor.execute("... %s", (v,))`, `$stmt->execute([$v])`: the value is not in the SQL
text). An unknown function is not followed.

**Across files.** A call that is handed the caller's value is followed into the project's own code, up to three calls deep, and the finding is reported at the
call with the place the value ends up ("... reaches the vulnerable call at app/db.py:8 (via report_for -> run_report)"). Python: `from .db import f`, `import app.db as d` then
`d.f()`, `from . import db`, `Class.method()` and the methods of classes the file imports (matched by name when exactly one matches). PHP: a plain function (one global
namespace: the one project function of that name), `Class::method()`, `$this->method()`, and `$object->method()` among the classes the file mentions (`use`, `new`, a type
hint, a promoted constructor property). The project's `.php` files are read once for names (no parse); a file is parsed only when a call leads to it.

**Checks clear the value.** Inside the branch a check guards, and after a failed check that stops the function (`return`, `raise`, `abort()`, `exit`, `die`, `throw`), the
checked name is not the caller's text: Python `x.isdigit()` / `isalnum()`, `x in COLLECTION`, `x == "literal"`, `re.fullmatch(...)`, an anchored `re.match`,
`isinstance(x, int)`, a function named `is_valid*` / `validate*` / `is_safe*`; PHP `is_numeric`, `ctype_*`, `in_array`, `filter_var(..., FILTER_VALIDATE_*)`, `preg_match` anchored at both
ends, `=== "literal"`. `a and b` checks both; `a or b` checks nothing. A check that does not say what the value IS (`startswith`, `strlen`, `array_key_exists`) does not clear it.

**Templates.** A value handed to a template (`render_template("page.html", name=v)`, `render(request, "page.html", {"name": v})`, Laravel `view("page", ["name" => $v])` / `compact()` / `->with()`) is
looked up in the project's `templates` / `resources/views` folder; it is cross-site scripting when the template prints that variable unescaped: `{{ name|safe }}`, `{{ name }}` inside
`{% autoescape off %}`, Blade `{!! $name !!}` (not when it is wrapped in `e()`, `htmlspecialchars`, `strip_tags` there). A template that is not found is not guessed.

| | Request input |
|---|---|
| Flask | `request.args`, `.form`, `.values`, `.json`, `.get_json()`, `.data`, `.cookies`, `.headers`, `.files`; the parameters of an `@app.route` / `@app.get` view (text, unless a converter such as `<int:id>` makes it a number) |
| FastAPI | the parameters of a path operation (path, query and body values); a parameter typed `int`, `float`, `bool`, `UUID`, a date (also `Optional[...]`, `List[...]`) is converted by the framework and is not input; `Depends(...)` and `Request` are not input |
| Django | `request.GET`, `.POST`, `.body`, `.COOKIES`, `.META`, `.FILES`, DRF `.data` / `.query_params`; the URL captures that come after `request` in a view |
| PHP | `$_GET`, `$_POST`, `$_REQUEST`, `$_COOKIE`, `$_FILES`, `$_SERVER` (only the keys a caller writes: `HTTP_*`, `REQUEST_URI`, `QUERY_STRING`, `PATH_INFO`), `php://input`, Laravel `$request->input() / get() / all() / only() / route()`; the parameters of a public controller method (not `int`-typed ones, not `Request` objects) |

| Rule | Python | PHP |
|---|---|---|
| `sql-injection` | `cursor.execute` / `executemany` / `executescript`, `Model.objects.raw`, `.extra`, `pandas.read_sql`, SQLAlchemy `session.execute(text(...))` with a built string | `mysqli_query`, `mysql_query`, `pg_query`, `->query` / `->exec` / `->prepare`, `DB::select / statement / raw / unprepared`, `whereRaw` / `selectRaw` / `orderByRaw` with a built string |
| `command-injection` | `os.system`, `os.popen`, `subprocess.*` with `shell=True`, `asyncio.create_subprocess_shell` | `system`, `exec`, `shell_exec`, `passthru`, `popen`, `proc_open`, backticks |
| `code-injection` | `eval`, `exec`, `compile`; request data as a template: `render_template_string`, `jinja2.Template`, `from_string` (server-side template injection) | `eval`, `assert`, `call_user_func`, `create_function`; `include` / `require` of a request-built path (file inclusion); `extract()` of request data |
| `insecure-deserialization` | `pickle.load(s)`, `marshal`, `dill`, `yaml.load` without a safe loader, `yaml.unsafe_load`, `shelve` | `unserialize` |
| `path-traversal` | `open`, `send_file`, `FileResponse`, `os.remove / listdir / ...`, `shutil.*`, `Path(x).read_text()` | `file_get_contents`, `fopen`, `readfile`, `file_put_contents`, `unlink`, `move_uploaded_file`, `copy`... |
| `ssrf` | `requests`, `httpx`, `urllib`, `aiohttp` (a URL whose scheme and host are written in the code is fine) | `curl_init`, `CURLOPT_URL`, Guzzle / `Http::get`, `fsockopen`, `get_headers` |
| `open-redirect` | `redirect`, `HttpResponseRedirect`, `RedirectResponse` (not when `url_has_allowed_host_and_scheme` or similar is used) | `header("Location: ...")`, `redirect()`, `Redirect::to` |
| `xss` | a returned HTML string in a view (Flask sends it as HTML), `HttpResponse`, `HTMLResponse`, `make_response`, `Markup`, `mark_safe` | `echo`, `print`, `<?= ?>` |
| `mass-assignment` | `Model.objects.create(**request.POST.dict())`, `User(**request.json)`, `.update(request.json)`, `insert_one(request.get_json())` (not when a form's `cleaned_data` / a serializer's `validated_data` / a schema's `.load()` is used) | `Model::create($request->all())`, `->fill`, `->update`, `firstOrCreate`... |
| `insecure-jwt` | `jwt.decode(..., verify=False)`, `verify_signature: False`, the `none` algorithm | `JWT::decode(..., ['none'])`, a payload read by `explode('.', $token)` and `base64_decode` |
| `csrf` | `@csrf_exempt` | `$except = ['*']`, `validateCsrfTokens(except: ['*'])`, `withoutMiddleware(VerifyCsrfToken)`, a Blade `<form method="post">` without `@csrf` (a form that includes a partial is not judged) |
| `debug-mode` | `app.run(debug=True)`, `DEBUG = True` (not when read from the environment) | `ini_set("display_errors", 1)`, `phpinfo()` |
| `hardcoded-secret` | provider token formats, `SECRET_KEY = "..."`, `password="..."`, dictionary entries | the same, `define("DB_PASSWORD", "...")`, array entries, properties |

**Shared variables.** A PHP script that `include`s / `requires` another one gets the variables the other leaves holding the caller's text (how DVWA builds its pages: `low.php` sets `$html`, `index.php` prints it). The path may be spelled out (`include 'lib/params.php'`) or built (`"source/{$level}.php"`): every file that fits the part the code spells out is read (up to 12), two includes deep. A write to one key of an array (`$page['body'] .= $x`) puts the text into the array. A route placeholder that is one URL segment (Flask `<name>`, FastAPI `{name}`) cannot carry a `/`, so it is not path traversal.

**Known limits.** A value is followed through calls to the project's own functions, not through `flask.g`, class attributes, or values stored in dictionaries or sessions; a validation inside a helper function that returns a boolean is only understood by its name; a decorator that
transforms the arguments is not understood; Django's ORM (`filter`, `get`) is treated as safe because it parameterizes (a `**kwargs` expansion
from request data is not examined); Python's `str.format` in an SQL string is reported, `sql.SQL(...).format(sql.Identifier(x))` (psycopg2) is not
recognised as safe and is reported; Twig templates and Django `{% autoescape %}` in a parent template are not read (a template that extends another is judged by its own text). Test files (`test_*.py`,
`*_test.py`, `conftest.py`, `*Test.php`) and `venv` / `site-packages` / `vendor` are skipped like JavaScript tests and `node_modules`.

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
  `req.currentUser` anywhere in it — nor a helper whose NAME shows an ownership check
  (`verifyCurrentUserHasAccessToPost(id)`, `checkOwnership`, `security.appendUserId()`), nor a deny-everything
  middleware (`security.denyAll()`). Skipped entirely for projects with no authentication library (there is no
  per-user data to reach through someone else's id) and for Next.js handlers that take no arguments.
  The check follows the handler: a route registered as `UserController.getUser` is looked up in the controller's
  file, and a helper it calls (`const access = await authorize(id)`, two levels deep) counts when it looks at the
  session or the user. A route behind an explicit role check (`checkRole(['Admin'])`, `authorize('ADMIN')`,
  `requireAdmin`) is skipped: which roles may see every record of a table is the developer's design, not something
  the code shows.
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

## `code-injection` (critical)

- **Sources:** same shared sources (see above).
- **Sinks:** `eval(...)`, `Function(...)` / `new Function(...)`,
  `vm.runInNewContext/runInThisContext/runInContext(...)`, `new vm.Script(...)`,
  and any `.eval(...)` method (`mathjs.eval`, `math.eval`, ...).
- **Not flagged:** `eval` of a constant, `JSON.parse(...)` of request data.
- Found in NodeGoat (`eval(req.body.preTax)`) and dvna (`mathjs.eval`).

## `open-redirect` (medium)

- **Sinks:** `res.redirect(...)` / `res.location(...)` (also `response`,
  `reply`, `ctx`), `NextResponse.redirect(...)`, `Response.redirect(...)`, and
  next/navigation's `redirect(...)` / `permanentRedirect(...)`; the target may
  be the second argument (`res.redirect(301, url)`).
- **Not flagged:** a target that starts with a fixed same-site path
  (`"/items/" + id`, `` `/items/${id}` ``): the host can't change. `"//" + x`
  and bare user input are flagged.
- **Known gap:** an allowlist/`startsWith("/")` check earlier in the function
  isn't recognised, so a correctly validated redirect is still reported.

## `nosql-injection` (high)

Two independent checks:

1. **Operator injection.** A MongoDB query method (`find`, `findOne`,
   `updateOne`, `deleteMany`, `aggregate`, ...) receiving `req.body` /
   `req.query` / `await request.json()` data that wasn't forced to a string.
   A JSON body `{"password": {"$ne": null}}` turns a value into a query
   operator. Not flagged: `req.params`/cookies/`searchParams.get()` (always
   strings), `String(x)`/`x.toString()`/template literals, and
   `{ field: { $eq: x } }` (the recommended defence — measured on
   hackathon-starter, where flagging it was a false positive). Skipped
   entirely when `package.json` shows a SQL driver/ORM and no MongoDB library
   (e.g. Sequelize: `db.User.find({ where: ... })` is not a Mongo query).
2. **`$where`.** A `$where` whose value is built from a dynamic value (template
   substitution / concatenation) runs attacker-influenced text as JavaScript
   inside the database. No source is needed: the input usually arrives through
   another file (NodeGoat), which per-function taint can't follow. Values
   coerced with `parseInt`/`Number`/`Math.*`/unary `+` (directly, or via a local
   variable initialised that way) are not flagged — that is the fixed NodeGoat
   version.

## `insecure-deserialization` (critical)

- **Sinks:** `unserialize(...)` / `.unserialize(...)` (node-serialize) and
  `deepDeserialize(...)` (funcster) — both revive functions and run them.
- `JSON.parse` is deliberately not flagged (it only builds data).
- Found in dvna (`serialize.unserialize(req.files.products.data...)`).
  `req.files` / `req.file` (uploads) are now part of the shared sources.

## `xxe` (high)

- **Sinks:** `parseXml` / `parseXmlString` / `parseXMLString` (libxmljs) **with
  `noent: true`** in the options, fed with request data. Entities stay off by
  default, so the same call without `noent` isn't flagged.
- Found in dvna (`parseXmlString(req.files.products.data..., {noent:true})`).

## `hardcoded-secret` (high / critical) — pattern match, no sink

Secrets typed into the source (or a committed `.env`) are the most common way a small project gets
breached: they sit in every clone and every old commit. Four kinds of evidence, strongest first:

| Evidence | Examples | Confidence |
|---|---|---|
| **Provider token formats** (found anywhere, comments included) | AWS access key IDs, GitHub tokens, Stripe live/test keys, OpenAI/Anthropic keys, Slack tokens and webhooks, SendGrid, npm and Telegram tokens, PEM private keys, database URLs with a password, **Supabase `service_role` keys** (decoded from the JWT: the public `anon` key is not flagged) | high |
| **Guessable signing secrets** | `jwt.sign(x, "secret")`, `jwt.verify(t, "...")`, `session({ secret: "keyboard cat" })`, `const JWT_SECRET = "your-secret-key"` (flagged even when it looks like a placeholder: a forgotten placeholder is the usual way this ships) | high |
| **Credentials by name** | a string that looks random (length, mixed character classes, entropy) assigned to `password`, `apiKey`, `accessToken`, `clientSecret`, ... | medium |
| **Browser-exposed secrets** | `process.env.NEXT_PUBLIC_..._SERVICE_ROLE_KEY` / `..._SECRET` / `..._PASSWORD` / `..._DATABASE_URL` (also `VITE_`, `REACT_APP_`, `EXPO_PUBLIC_`, ...): the build copies these into the JavaScript every visitor downloads | high |

**`.env` files** (`.env`, `.env.local`, `.env.production`, ...; templates such as `.env.example` are skipped): a
file holding real-looking values is reported as **critical when it is committed to git**, **high when it is
not ignored** (one `git add .` away), and not at all when `.gitignore` covers it — the correct setup. Without
git it falls back to reading `.gitignore`.

**A secret is never printed in full.** Messages, snippets, JSON, HTML, SARIF, annotations and the pull
request comment show only a recognisable head (`sk-a…[40 chars redacted]`), because a report posted on a
public pull request would otherwise publish the leak. Every message tells you to treat the value as already
leaked and rotate it — deleting the line does not remove it from the git history.

What it deliberately does not flag: placeholders (`your-api-key`, `changeme`, `${VAR}`, documentation
examples like `AKIAIOSFODNN7EXAMPLE`), local development databases (`localhost`), URLs and paths, lowercase
identifier-style values (`same-origin`), public-by-design keys (Supabase `anon`, Stripe publishable,
`NEXT_PUBLIC_*_PUBLISHABLE_KEY`), Google/Firebase `AIza` web keys (the Firebase config object is recognised by its
sibling `authDomain` / `projectId` + `appId` fields), a PEM header such as `-----BEGIN PRIVATE KEY-----` with no key
body after it (code that merely checks the format), constants named as development stand-ins
(`DEV_ONLY_JWT_SECRET`), and test folders and test scripts (`*.test.ts`, `test-suite.ts`, `login-test.js`). It cannot see a secret that
is built at run time, and entropy-based detection will miss low-entropy passwords outside the signing-secret and
known-format cases.

## `supabase-rls` (critical / high / medium) — reads your SQL migrations

Supabase serves every table of an exposed schema (`public` by default) through an auto-generated REST API that
anyone holding the project's **public** anon key can call — and that key ships in the browser. Row Level Security
is the only thing between the internet and the data, so a table without RLS is an open table, and a policy that
says `USING (true)` is the same thing with extra steps. The scanner reads `supabase/migrations/*.sql` (and any
SQL file in a project that depends on `@supabase/*` or uses `auth.uid()` / `TO anon`) **as one timeline** and
reports the state that is left after every migration has run.

| Finding | Severity |
|---|---|
| Table in an exposed schema, RLS never enabled (critical, medium confidence) or explicitly `DISABLE`d (critical, high confidence) | critical |
| Policy `FOR ALL / UPDATE / DELETE ... USING (true)` for `anon` / `public` (the default when there is no `TO`) | critical |
| The same for `authenticated` (any signed-in user, anonymous sign-ins included) | high |
| `INSERT ... WITH CHECK (true)` for `anon` / `public`; `SELECT USING (true)` for `anon` on a table that looks personal (email, phone, orders, profiles, ...) | high |
| UPDATE / DELETE / ALL policy that only checks `auth.uid() IS NOT NULL` or `auth.role() = 'authenticated'` ("signed in" is not ownership) | high |
| A policy that decides from `user_metadata` / `raw_user_meta_data` (users can edit it themselves; use `app_metadata`) | high |
| View over an RLS table without `security_invoker = true` (runs with its owner's rights, bypasses RLS); materialized views | high |
| `storage.objects` write policy without an owner check (anyone / any signed-in user can overwrite or delete files) | high / medium |
| `SECURITY DEFINER` function in an exposed schema without `SET search_path` (trigger functions excluded) | medium |

It stays quiet for: schemas that are not exposed (`supabase/config.toml` `[api] schemas` is honoured), tables
revoked from the API roles (`REVOKE ... FROM anon, authenticated`), projects that switch RLS on automatically with
an event trigger, partitions and tool tables (`schema_migrations`, `spatial_ref_sys`, ...), owner-scoped policies
(`(select auth.uid()) = user_id`), and public `SELECT` policies on public-looking data. **Limits:** it sees the
migrations, not the live database — a table fixed in the dashboard but not in a migration is still reported, and
RLS written in application-level code or generated by a tool it does not read is invisible to it.

When the code shows that Supabase is used **only from a server** (`@supabase/supabase-js` is imported but nothing
puts the anon key in the browser: no `NEXT_PUBLIC_SUPABASE_*` / `VITE_SUPABASE_*`, no browser client, no
`"use client"` file), the table finding drops to medium with low confidence: the anon key is not published by the
app, so a missing policy is a safety net that is missing rather than an open door.

## `supabase-auth` (high / medium) — server code

- `supabase.auth.getSession()` in server code in a file that never calls `getUser()`: the session
  comes straight from the cookie and is **not verified** with Supabase's auth server, so a forged cookie passes. Use
  `getUser()`. (medium) A file counts as server code when it lives under `api/`, `server/`, `actions/` or is a
  `route.ts` / middleware, or imports `next/headers`, `next/server`, `createServerClient`, Express, Fastify, Koa,
  Hono or similar. Browser code (`"use client"`, a hook, a context, a single-page app) is skipped: calling
  `getSession()` there is the normal way to read the signed-in user.
- A role or permission read from `user_metadata` (`user.user_metadata.role === "admin"`, also `is_admin`, `plan`,
  `tier`, `permissions`): users can rewrite their own `user_metadata` from the browser. Use `app_metadata` or a
  roles table. (high)

## `firebase-rules` (critical / high / medium) — Firestore, Storage, Realtime Database

The Firebase config of an app (apiKey, projectId, ...) is public **by design**; the security rules are all that
protects the data. Checked files: `firestore.rules`, `storage.rules` (and any `*.rules` with a
`service cloud.firestore` / `service firebase.storage` header), `database.rules.json`.

| Finding | Severity |
|---|---|
| `allow read, write: if true;` (or `allow write;` with no condition) | critical |
| The console's **test-mode** rule `if request.time < timestamp.date(...)`: critical until the date, medium after it (expired rules deny everything; moving the date is not a fix) | critical / medium |
| `if request.auth != null` as the only condition for `update` / `delete` / `write` (any signed-in user, including anonymous sign-ins, can change anyone's data); critical at the root `/{document=**}` | high / critical |
| Public or signed-in-only **reads** of a private-looking collection (`users`, `orders`, `messages`, `payments`, ...) or of everything | medium / high / critical |
| `update` / `delete` / `write` whose condition never mentions `request.auth` (only the shape of the data is validated: `hasOnly([...])`, size limits): any visitor, signed in or not, can change the documents | high / critical |
| A public read (`if true`) of documents whose fields hold personal or financial data (phone, ID number, e-mail, address, bank, ...), found by reading the field names in the rule and the helpers it calls, whatever the collection is called | high |
| Realtime Database `.read` / `.write` set to `true` at the root or under a path; `auth != null` at the root | critical / high |

Zero-argument helpers such as `function ok() { return request.auth != null; }` are expanded before the condition is
judged. A rule that looks the caller up in another document (`get(...)`, `exists(...)`) is never reported as
"no auth": the lookup may well be the admin check.

Owner checks (`request.auth.uid == userId`, `resource.data.ownerId`, `$uid === auth.uid`), helper functions
(`isOwner(...)`), create-only rules (a public form is a design choice) and public reads of public-looking
collections are not flagged. A Firebase
**service-account key** (`*-firebase-adminsdk-*.json`: `"type": "service_account"` with a `private_key`; it bypasses
every rule) or a Google OAuth client-secret file committed to git is reported by `hardcoded-secret` (critical when
tracked, high when not ignored).

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
- `markdown` — the pull-request-comment report (score, table, collapsed AI prompt).
- `github` — one `::error` / `::warning` / `::notice` workflow annotation per finding.
- `prompt` — **one prompt for your AI assistant** covering every finding (most severe first): file and line,
  what is wrong, the code, how to fix it, and requirements ("change only what is needed, show the diff").
  Paste it into Cursor / Claude / Copilot. It is built from the already redacted fields, so it never contains
  a secret. The HTML report and the web interface have the same thing as a button on each finding
  ("Copy prompt for my AI assistant") and one for all findings; the pull-request comment has it in a collapsed
  block.

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
