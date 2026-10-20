# Changelog

Both packages (`security-hub-scanner`, `security-hub`) are released together at the same version.

## Unreleased

### Fixed
- **Python: `use_case.execute(command)` is no longer SQL injection.** `execute` / `executemany` counts as a database call only when the receiver looks like a database
  handle (`cursor`, `conn`, `db`, `session`, `engine`, ...) or the argument is SQL text being built. Clean-architecture FastAPI projects, which name their use cases `.execute(...)`,
  produced 7 false findings in 27 layered projects (validation round 14).
- Demo logins (a password on a line with an `@example.com` / `@test.com` address), `dev-only` and `stub-` values and `e2e` files are not leaked credentials.
- Python: a redirect built on a configured host (`f"{frontend_base_url}/..."`, `settings.SITE_URL + path`) is not an open redirect.

## 0.7.1 - 2026-10-20

### Changed
- **Python and PHP follow data across files.** A call that is handed the caller's value is followed into the project's own code, up to three calls
  deep, and the finding is reported at the call with the place the value ends up ("reaches the vulnerable call at app/db.py:8 (via report_for ->
  run_report)"). Python: `from .db import f`, `import app.db as d`, `from . import db`, methods of imported classes. PHP: global functions,
  `Class::method()`, `$this->service->method()`, services injected into a controller. The names of the project's PHP functions are read once from
  the text (no parse); a file is parsed only when a call leads to it.
- **Value checks clear the taint:** Python `isdigit()`, `in COLLECTION`, `== "literal"`, `re.fullmatch`, `isinstance`, `is_valid*()`; PHP `is_numeric`,
  `ctype_*`, `in_array`, `filter_var(FILTER_VALIDATE_*)`, an anchored `preg_match`; inside the branch the check guards, and after a failed check that
  stops the function (`return`, `raise`, `abort()`, `exit`, `die`, `throw`). A check that does not say what the value is (`startswith`, `strlen`,
  `array_key_exists`) clears nothing.
- **Templates are read.** A value handed to `render_template` / `render` / Laravel `view()` that the template prints unescaped (`{{ x|safe }}`,
  `autoescape off`, Blade `{!! $x !!}`) is cross-site scripting.
- **New checks:** Python mass assignment (`Model.objects.create(**request.POST.dict())`, `User(**data)`, `insert_one(request.get_json())`); PHP `JWT::decode`
  with the `none` algorithm or a payload read without verification, CSRF switched off (`$except = ['*']`, `validateCsrfTokens(except: ['*'])`), Blade
  forms without `@csrf`.
- Less noise: a controller parameter typed with a class is a record Laravel loaded (route-model binding), not the caller's text; a Blade form that
  includes a partial is not judged; `{!! e(...) !!}` is not a raw print; `DEBUG = True` in a `dev` / `test` settings file is not reported.
- Dependabot: the `tree-sitter` family and `@types/vscode` are updated by hand (a "minor" bump of a 0.x parser package breaks the build); GitHub
  Actions updated (checkout 7, setup-node 7, codeql-action 4, the Pages actions).

Measured on the 25 Python and PHP projects of the validation (docs/validation.md, round 13). The cross-file flow is tested on fixtures; no real project
in that sample needed it, so its precision and recall on real code are not measured.

## 0.7.0 - 2026-10-15

### Added
- **The scanner runs in the browser.** On the website, drop a project folder and it is scanned on your computer, with no
  install and no upload: the real scanner sources bundled for the browser, tree-sitter as WebAssembly in a Web Worker,
  the dropped files in an in-memory `fs`. Same findings as the command line (compared on the four example projects and 30
  real repositories), a fix prompt per finding, a progress bar, a downloadable JSON report, and a list of the files that
  were skipped or only partly analysed. Only the grammars the project needs are downloaded. See
  [docs/web-scanner.md](docs/web-scanner.md).
- `scanPath(..., { onProgress })` reports progress file by file.
- **Armo in the pull request comment** and the job summary: the mascot beside the score, in the mood of the score (the
  pictures are the ones the website serves). The Action's `mascot: false` leaves it out.
- **`.security-hub.json`**: a project's own settings (`ignore`, `disable`, `severity`, `failOn`, `includeTests`), read by
  `scan`, the Action and the in-browser scanner; flags and inputs win over it; `--config <file>`, `--no-config`; a typo is
  an error. Disabled rules are counted in the report (`disabledCount`). JSON schema in `docs/`.
- **`security-hub baseline`** and `.security-hub-baseline.json`: record today's findings so `scan` and the Action report
  only new ones (`--baseline <file>`, `--no-baseline`, the Action's `baseline` input); the report says how many old findings
  are hidden and how many baseline entries went stale. Findings are matched by rule, file and line text, never by a secret's value.

- **Frameworks:** SvelteKit (`+server`, form actions, `load`), Remix / React Router (`loader`, `action`), Nuxt / Nitro (h3 readers,
  `server/api`), tRPC (`input` of resolvers) and Hono are understood: their way of reading the request feeds every data-flow rule,
  and handlers that change data without checking the caller (`broken-access-control`) or change another user's record (`idor`) are
  reported, with SvelteKit hooks / Nuxt middleware that enforce sign-in counting as the check. Prisma `$queryRawUnsafe` /
  `$executeRawUnsafe` are SQL sinks. Fixture: `examples/vulnerable-frameworks`.
- **`fix` handles `xss` and `open-redirect`**: values that go into HTML are wrapped in `escapeHtml(...)`, redirect targets in
  `safeRedirect(...)` (only a same-site path passes), each with a small helper added to the file; the result is checked by scanning
  again. A value that passes through another call, or reaches the sink in another file, is left to you with the reason. The taint
  tracker treats `safe*`, `validate*` and `verify*` calls like `escape*` and `sanitize*`: their result is not followed.
- **VS Code extension (early)**, `packages/vscode`: findings in the Problems panel, the score in the status bar, a quick fix that copies the
  fix prompt. Off in untrusted workspaces; its command setting cannot be set by a workspace. `scan --format json --prompts` adds the prompt to each finding.
  Logic tested here, not yet run inside an editor.
- **Python and PHP.** Flask, FastAPI and Django, plain PHP scripts and Laravel are scanned: SQL / command / code / template injection,
  deserialization, path traversal, SSRF, open redirect, reflected XSS, mass assignment (Laravel), `@csrf_exempt`, JWT without verification,
  debug mode and hard-coded secrets, in the same report, score, ignore comments, baseline and web scanner. Typed FastAPI parameters and Flask
  converters are understood as safe; helpers in the same file are followed one call deep, other files are not yet. The grammars are optional
  packages: a machine that cannot install one lists those files as skipped. New rule `debug-mode` (30 rules in all). Fixtures:
  `examples/vulnerable-python-app`, `examples/vulnerable-php-app`; see docs/rules.md and docs/validation.md.
- **Four new rules (29 in all, before `debug-mode`):** `mass-assignment` (the whole request body written to the database), `prototype-pollution`
  (request data deep-merged or used as nested keys), `webhook-signature` (Stripe / Lemon Squeezy / Paddle handlers that never verify
  the signature), `insecure-token-storage` (a login token in `localStorage` / `sessionStorage` / a script-set cookie).

### Changed
- The scanner no longer needs Node's `Buffer` (a JWT payload is decoded with `atob`, the head of a public file is read
  into a `Uint8Array`); the website's script policy allows a Web Worker from the same site (`worker-src 'self'`).
- The Pages workflow builds `site/scanner/` (`npm run site:scanner`) and also runs when the scanner changes.

## 0.6.0 - 2026-10-15

### Security (a review of the project itself, see [docs/security-audit.md](docs/security-audit.md))
- A crafted file can no longer crash or hang a scan: iterative tree walk, a 20 s parse limit, a 15 s analysis budget per
  file, each check guarded on its own, a cap of 500 secret findings per file, and the quadratic behaviours found with
  hostile inputs removed. A file that cannot be finished is reported as incomplete, never as clean.
- The native parser is loaded once per process and shared. Before, a second module registry (a test runner, or an application
  holding two copies of the package) loaded the addon again and got trees without a root.
- `security-hub ui`: the token is no longer inside the page (any other user of the machine could read it); it travels in
  the link's `#fragment`. The link printed in the terminal contains it.
- "Fix with AI" prompts tell the assistant that text copied from the project is untrusted data, and strip hidden
  characters (zero-width, bidirectional, Unicode tags) from it.
- git is run with `core.fsmonitor` off inside scanned folders; `fix --write` refuses symbolic links, creates `.env` as
  `0600` and git-ignores its `.security-hub.bak` backups.
- The SQL-injection lab is published on `127.0.0.1` only and runs as a non-root user; the site allows its one inline script
  by hash; CI runs with read-only permissions; test tooling moved to jest 30 (0 vulnerabilities in the published
  packages, 0 critical or high anywhere); `SECURITY.md` and Dependabot added.

### Added
- **`scan --audit`** (optional, 25th rule `vulnerable-dependency`): known vulnerabilities in your dependencies from npm's
  advisory database, one finding per vulnerable direct dependency on its line in `package.json` (installed version,
  advisories, the fix) and one summary for the transitive ones. It is the only feature that uses the network (`npm audit`
  sends dependency names and versions to the registry), so it runs only with the flag.
- **`security-hub fix`**: fixes what can be fixed mechanically and safely: SQL values become bound parameters (`$1`,
  `?`, Sequelize `replacements`), JWTs get an expiry and lose `none` / `ignoreExpiration`, hard-coded secrets move to
  `.env` (value) / `.env.example` (name) / `.gitignore`, permissive CORS reads `ALLOWED_ORIGINS`, and Supabase tables
  without RLS get one migration with `ENABLE ROW LEVEL SECURITY`. It shows a diff and changes nothing without
  `--write`; never prints a secret; refuses to touch files with uncommitted git changes (`--force`), or keeps
  `.security-hub.bak` copies without git; and ends with a TODO list (rotate the moved secrets, write the policies).
- **Four new rules (24 in total)**: `insecure-cors` (any origin accepted together with credentials), `insecure-jwt`
  (`none` algorithm, `ignoreExpiration`, `jwt.decode()` trusted without `verify`, tokens that never expire),
  `missing-rate-limit` (a sign-in or code-check endpoint that checks the credential itself, in a project with no rate
  limiting anywhere) and `exposed-files` (`.env`, keys, dumps and `.git` in `public/` or an `express.static` folder,
  `express.static(__dirname)` at the project root). See [docs/rules.md](docs/rules.md).
- **Next.js Server Actions**: the arguments of a `"use server"` function are request input for every data-flow rule, and
  an action that changes data without checking the caller is reported (`broken-access-control`), or one that changes the
  record whose id the browser sent without comparing it with the caller (`idor`).
- **Taint through return values**: `const q = buildQuery(req.query.name); db.query(q)` and `db.query("..." + getId(req))`
  are followed (same precision rule: only a value used directly in the returned expression counts; helpers that
  sanitise, validate, check or hash are never followed). `asyncHandler(...)` / `cache(...)` wrappers resolve to their
  function, and conditions, comparisons and negations no longer carry a value.
- **Armo's real artwork** replaces the placeholder shield on the website, in the HTML report and in `security-hub ui`: three transparent 256 px PNGs (curled up, nervous, alarmed) cut from the generated picture.
- **Armo, the mascot** (an armadillo): shown in the HTML report and in `security-hub ui`, curled up when the score is
  good, nervous when it needs attention, alarmed when the project is at risk. The images are embedded (`npm run mascot`
  rebuilds them from `site/assets/`), so the report is still one file that makes no network request.
- `firebase-rules` reports writes that never mention `request.auth` (only the shape of the data is validated) and
  public reads of documents that hold phone numbers, ID numbers, e-mails or bank details, whatever the collection
  is called; zero-argument helper functions such as `ok()` are expanded first.

### Changed (fewer false findings, from validating 16 real vibe-coded projects, see docs/validation.md round 9)
- First pass on those projects: 118 findings, 20% real. After the changes below: 40 findings, all real or reasonable.
- `idor` follows the handler into the controller file and its helpers, and skips routes behind an explicit role check.
- `csrf` reads the whole project: a csrf middleware registered in another file, an `Authorization`-header API that
  never reads cookies, and Firebase / Supabase-client apps no longer produce findings.
- `hardcoded-secret` ignores the Firebase web config `apiKey`, a PEM header with no key body, `DEV_ONLY_*` constants
  and test scripts (`test-suite.ts`).
- `supabase-auth` reports `getSession()` only in server code; `broken-access-control` accepts a shared-secret header
  check; `supabase-rls` lowers a table without RLS to medium when the app uses Supabase only from a server.

## 0.5.0

The first release since 0.3.0: it contains everything below, including the work that was prepared as 0.4.0 (that
version was never published). `security-hub-scanner` and `security-hub` are both 0.5.0.

### Added
- **Supabase and Firebase rules** (3 new rules, 20 in total): `supabase-rls` reads your SQL migrations as one
  timeline and reports tables served by the API without Row Level Security, `USING (true)` and "signed in only"
  policies, `user_metadata` in policies, views without `security_invoker`, open storage policies and
  `SECURITY DEFINER` functions; `supabase-auth` flags `getSession()` trusted on the server and roles read from
  `user_metadata`; `firebase-rules` checks `firestore.rules`, `storage.rules` and `database.rules.json`
  (`if true`, test-mode rules, signed-in-only writes, open private paths). A Firebase service-account key or OAuth
  client secret committed to git is reported by `hardcoded-secret`. See [docs/rules.md](docs/rules.md).
- `firebase-rules` was checked against six official Firebase sample repositories (49 rules files): `request.auth.uid != null`
  now counts as signed-in-only, and open reads of all Storage files / of chats rank lower than open reads of users or
  orders. See [docs/validation.md](docs/validation.md#round-8-firebase-rules-on-six-official-projects).
- Project facts read from `package.json` are now cached per file *modification*, so a long-running
  `security-hub ui` follows edits instead of using the first scan's answer forever.
- `broken-access-control` recognises `supabase.auth.getUser()` / `getSession()` and Firebase `verifyIdToken` as
  access checks; a `secret` property counts as a signing secret only in calls about sessions, tokens or auth.

- **`hardcoded-secret` rule** (17th): provider token formats (AWS, GitHub, Stripe, OpenAI/Anthropic, Slack,
  SendGrid, npm, Telegram, PEM private keys, database URLs with a password, Supabase `service_role` keys),
  guessable `jwt.sign` / `session` secrets, credentials assigned to `password` / `apiKey` / `token` names,
  secrets behind browser-exposed env prefixes (`NEXT_PUBLIC_…_SECRET`), and `.env` files that are committed to
  git or not gitignored. Secrets are always redacted in every output. See
  [docs/rules.md](docs/rules.md#hardcoded-secret-high--critical--pattern-match-no-sink).

- **"Fix with AI" prompts.** Every finding comes with a ready-to-paste prompt for Cursor / Claude / Copilot
  (file, line, problem, code, how to fix, requirements): a copy button per finding and one for all in the web
  interface and HTML report, a collapsed block in the pull request comment, and `--format prompt` on the command
  line. Prompts never contain secrets.

### Changed (precision and coverage, from the second validation round)
- **Far fewer false positives on real projects** (194 → 54 findings on nine unseen repositories, with 128 → 0 false
  ones; see [docs/validation.md](docs/validation.md#round-6-nine-more-projects-first-pass-vs-second-pass)).
  `csrf` is skipped where the browser attaches no credential by itself (no auth library; Auth.js / Clerk /
  Supabase SSR and other `SameSite=Lax` cookie frameworks; webhooks; `denyAll()` routes). `idor` recognises
  ownership helpers by name, `denyAll()`/`appendUserId()` middleware, skips projects with no authentication library
  and Next.js handlers that take no argument. `hardcoded-secret` ignores error codes, password hashes and
  placeholder deny-lists. `username-enumeration` requires a login flow.
- **Taint sinks only look at the dangerous argument** (`db.query(sql, values)`: the text; `fs.writeFile(path, data)`:
  the path; `redirect(url, { headers })`: the URL), and values that went through `parseInt`, hashing, escaping /
  sanitising, an allowlist check or a table lookup by key are no longer tainted.
- **More sources:** destructured handler parameters (`({ body, file }: Request, res)`, Remix `({ request, params })`,
  Next.js `GET(request, { params })`), Fastify `request.*`, Koa `ctx.*`, Hono `c.req.*`.
- **More sinks:** `res.sendFile()` / `res.download()` and more `fs` calls (`readdir`, `stat`, `rm`, `rename`, ...)
  for path traversal.

## 0.4.0 (never published; included in 0.5.0)

### Added
- **Taint across functions and files.** Request data is followed into the project functions it is passed to —
  same file or another one — and reported at the call site together with the location of the vulnerable call.
  Resolves ES-module and CommonJS imports, `@/` and tsconfig `paths` aliases, barrel files, object literals,
  classes (`extends`, `this.method()`), constructor functions, up to six calls deep. Return values and callbacks
  are not followed. See [docs/rules.md](docs/rules.md#how-data-is-followed-across-functions-and-files).
- **GitHub Action** (`dam1r-dev/security-testing-hub`): scans pull requests, reports only what the change touches
  (the whole project is still analysed), inline annotations, one self-updating summary comment, job summary,
  optional SARIF upload, `fail-on` gate. See [docs/github-action.md](docs/github-action.md).
- **Silencing findings:** `// security-hub-ignore [rule-id] [-- reason]` comments, a `.security-hub-ignore` file,
  `--ignore <pattern>`, and `--include-tests`. Hidden findings are counted in every report.
- **CLI:** `--changed-since <ref>` (report only files changed vs. a git ref), `--format markdown` and
  `--format github` (workflow annotations).
- **Web interface:** shows how many findings were hidden by ignore comments.

### Fixed
- `nosql-injection` no longer flags `users.find((u) => u.name === req.body.name)` (`Array.prototype.find` with a
  predicate was mistaken for a MongoDB query). This false positive existed in 0.2.0 and 0.3.0.
- `ssrf` and other taint rules no longer treat a value looked up by a user-chosen **key** (`CONFIG[req.params.name]`)
  as user-controlled.
- `xss` no longer flags `res.send({ ... })` / `res.send([...])`: an object response is JSON, not HTML.
- `const { id } = req.params` now taints `id` (destructuring was silently dropped), and shorthand properties
  (`User.findOne({ username })`) count as a use of the variable.
- SARIF file paths are repository-relative when scanning an absolute folder (GitHub code scanning needs that),
  and the SARIF `version` field reports the real tool version.
- Files over 2 MB (bundles, generated output) are skipped with a visible warning instead of taking minutes.
- Scans are faster: rules share one walk of each function (e.g. 2.0 s → 1.2 s on nextjs-subscription-payments).

## 0.3.0
- `security-hub ui`: local web interface (folder picker, score, filters, HTML report download; EN/RU/KK).

## 0.2.0
- Five new rules: code injection, open redirect, NoSQL injection, insecure deserialization, XXE (16 rules total).

## 0.1.2 and earlier
- First public releases: SQL injection, XSS, command injection, path traversal, SSRF, CSRF, IDOR, broken access
  control, insecure role assignment, insecure file upload, username enumeration; Next.js App Router support;
  0–100 score; text / JSON / SARIF / HTML output.
