# Changelog

Both packages (`security-hub-scanner`, `security-hub`) are released together at the same version.

## Unreleased

### Added
- **Supabase and Firebase rules** (3 new rules, 20 in total): `supabase-rls` reads your SQL migrations as one
  timeline and reports tables served by the API without Row Level Security, `USING (true)` and "signed in only"
  policies, `user_metadata` in policies, views without `security_invoker`, open storage policies and
  `SECURITY DEFINER` functions; `supabase-auth` flags `getSession()` trusted on the server and roles read from
  `user_metadata`; `firebase-rules` checks `firestore.rules`, `storage.rules` and `database.rules.json`
  (`if true`, test-mode rules, signed-in-only writes, open private paths). A Firebase service-account key or OAuth
  client secret committed to git is reported by `hardcoded-secret`. See [docs/rules.md](docs/rules.md).
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

## 0.4.0

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
