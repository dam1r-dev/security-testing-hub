# Validation on real open-source projects

The MVP success criteria asked for testing on "10+ real Node.js projects".
This is the first round (6 projects), run with the published `security-hub@0.1.1`
and then again after the fixes below. It is a **small sample** — treat the
numbers as a direction, not a benchmark.

## Method

Shallow clones (`git clone --depth 1`), static analysis only: nothing was
installed or executed. Every finding was read in its source context and
labelled true or false positive by hand.

| Project | Why it's in the set |
|---|---|
| [OWASP/NodeGoat](https://github.com/OWASP/NodeGoat) | Deliberately vulnerable Express app — shows what we *miss* |
| [appsecco/dvna](https://github.com/appsecco/dvna) | Deliberately vulnerable Express app — same |
| [gothinkster/node-express-realworld-example-app](https://github.com/gothinkster/node-express-realworld-example-app) | Ordinary Express + TypeScript API (JWT auth) |
| [sahat/hackathon-starter](https://github.com/sahat/hackathon-starter) | Large, mature Express boilerplate |
| [vercel/next-learn](https://github.com/vercel/next-learn) | Next.js (many small example apps) |
| [vercel/nextjs-subscription-payments](https://github.com/vercel/nextjs-subscription-payments) | Next.js App Router + Supabase + Stripe |

## Round 1 (0.1.1): 40 findings, 18 false positives (45%)

| Cause | Findings | Fix |
|---|---|---|
| CSRF reported once per route (12 on one controller, same root cause) | counted as noise | one finding per file |
| CSRF on a pure JWT-in-header API (realworld) | 12 FP | skipped when `package.json` shows bearer auth and no cookie/session library |
| CSRF on a Stripe webhook (signature-authenticated) | 1 FP | webhook routes skipped |
| `username-enumeration` on **test files** (Cypress / mocha specs) | 3 FP | test dirs and `*.test.*` / `*.spec.*` skipped |
| IDOR on `/account/unlink/:provider` ("provider" contains "id") | 1 FP | id params must be named `id` or end in `Id`/`ID`/`_id` |
| Broken access control on `/dashboard` behind `isLoggedIn` | 1 FP | `isLoggedIn`-style guards recognised; plain `/dashboard` is no longer treated as privileged |
| Scanning vendored `jquery.min.js` etc. | 7.4 s on a 50-file project | `vendor/` and `*.min.js` skipped |

## Round 2 (after fixes): 7 findings, 0 false positives

| Project | Before | After | What remains |
|---|---|---|---|
| NodeGoat | 10 (75/100, 7.4 s) | 3 (93/100, 0.4 s) | CSRF, IDOR (`/allocations/:userId`), username enumeration — all real |
| dvna | 14 | 4 | SQL injection, command injection, CSRF x2 — all real |
| node-express-realworld | 12 | 0 | — |
| hackathon-starter | 3 | 0 | — |
| next-learn | 0 | 0 | — |
| nextjs-subscription-payments | 1 | 0 | — |

**Caveat on "0 false positives":** it is measured on 6 projects and the fixes
were tuned on exactly these findings, so it will not generalise perfectly.
The next round on different projects is the real test.

## Round 3: five new rules (code injection, open redirect, NoSQL injection, deserialization, XXE)

Written against the misses listed below, using the real code from the two
vulnerable apps as the cases. Every planted bug of those five classes is now found:

| Project | Round 2 | Round 3 | Newly found |
|---|---|---|---|
| NodeGoat (score 93 -> 41) | 3 | 8 | `eval` x3 (contributions.js), open redirect (`/learn`), `$where` injection (allocations-dao.js) |
| dvna (score 69 -> 31) | 4 | 8 | `mathjs.eval`, open redirect, `unserialize`, XXE (`noent:true`) |
| the other four projects + JumaTime | 0 | 0 | — |

Two false positives showed up on the way and were fixed before release, each
with a regression test: MongoDB-operator checks fired on dvna's Sequelize
`find({ where: ... })` (now skipped for SQL-only projects), and on
hackathon-starter's `findOne({ email: { $eq: req.body.email } })`, which already
is the recommended defence (now recognised).

## Round 4: taint across functions and files

The engine now follows request data into project functions and across files (see
[rules.md](rules.md#how-data-is-followed-across-functions-and-files)). Re-running the
six projects: **no new true findings and one new false positive, fixed before release.**
That is the honest result of this corpus, not a flaw in the feature — none of the six
projects keeps its SQL/command/path sinks in a separate layer from the route handlers
(NodeGoat and dvna put the vulnerable calls next to the request handling; the Next.js
and realworld apps use an ORM). The cross-file logic is therefore verified on purpose-built
cases (`packages/scanner/tests/cross-file.test.ts`, 30 cases, and the `reports` / `orders`
routes in the two example apps) and still needs a round on projects that do have a service
layer.

False positives the new analysis exposed, each fixed with a regression test:

| Finding | Cause | Fix |
|---|---|---|
| `ssrf` in hackathon-starter (`revokeProviderTokens(provider, ...)`) | the tainted value was only a **key into a constant table** (`CONFIG[providerName]`); the URL came from the table | a value looked up by a user-chosen key (`table[key]`) is no longer tainted — also applies inside a single function |
| `xss` on `res.send({ status, amount, to })` (example app) | an object/array response is JSON, not HTML | `res.send(object \| array)` is not an XSS sink |
| `nosql-injection` on `users.find((u) => u.name === req.body.name)` (my own demo shop, present since 0.2.0) | `Array.prototype.find` with a predicate matched the MongoDB `find` name | a function as the first argument means "not a MongoDB query" |

Two improvements to the single-function engine came with it, and they find more real bugs:
`const { id } = req.params` now taints `id` (destructuring was silently dropped before) and a
shorthand property in a query (`User.findOne({ username })`) counts as a use of the variable.

Scan time did not regress: the same rules share one walk of each function now
(hackathon-starter 2.6 s -> 2.2 s, nextjs-subscription-payments 2.0 s -> 1.2 s).

## Round 5: hard-coded secrets (`hardcoded-secret`)

Run on the same six projects plus JumaTime and this repository itself.

| Project | Findings | Verdict |
|---|---|---|
| NodeGoat | 4 (`cookieSecret`, a ZAP API key, a seed admin password) | all real hard-coded credentials (deliberately vulnerable app) |
| dvna | 1 (`session({ secret: 'keyboard cat' })`) | real |
| the other four + JumaTime | 0 | JumaTime's `.env` is correctly gitignored |

Two false positives showed up and were fixed with regression tests before release:
- `fetch(url, { credentials: "same-origin" })` (nextjs-subscription-payments): the name `credentials` is a fetch
  option, and `same-origin` looked random enough. `credentials` is no longer a credential name, and
  lowercase-words-joined-by-`-`/`_` values are treated as identifiers.
- A comment in this repository's own source that quoted `process.env.NEXT_PUBLIC_X_SECRET` as an example was read
  as a use of that variable. Mentions inside comments no longer count for the browser-exposed-variable check
  (known token formats are still matched in comments on purpose).

Same caveat as before: the rule was tuned on these projects, so treat "5 real, 0 false" as direction, not a rate.

## Round 6: nine more projects, first pass vs. second pass

This round was run on projects the rules had never seen, to find out what the numbers really look like.
Nine shallow clones (read-only, nothing installed or executed): OWASP Juice Shop (deliberately vulnerable,
398 files), Prisma examples (656 files), and seven ordinary projects — `node-express-boilerplate`,
`bulletproof-nodejs`, `nestjs-boilerplate`, Vercel `ai-chatbot` and `commerce`, `taxonomy`, `chatbot-ui`.
Every finding was read in its code and labelled **real**, **reasonable** (the pattern is genuine and an auditor
would check it, e.g. no ownership check visible), **debatable**, or **false**.

**First pass, rules untouched: 194 findings — 45 real or reasonable (23%), 21 debatable (demo apps with no authentication at all), 128 false.**

| Cause of the false positives | Count | Fix |
|---|---|---|
| CSRF on Next.js / demo projects (Lax cookies, or no cookies at all) | 40 | skip when the credential is not attached by the browser (see [rules.md](rules.md#csrf-medium--heuristic-not-taint-based)) |
| IDOR on routes blocked by `denyAll()` or scoped by `appendUserId()` / a `verify…Access` helper | 63 | recognise those by name; skip projects with no authentication library; skip handlers that take no argument |
| `hardcoded-secret`: error codes (`'incorrectPassword'`), bcrypt hashes in seed files, a deny-list of placeholder secrets | 11 | camelCase values that name the thing they describe, password-hash formats, containers named `placeholder`/`example`/... |
| SQL / path traversal: the safe parts of a call counted as dangerous (`query(sql, { replacements })`, `writeFile(path, data)`, `createReadStream(p, { start })`), hashed or allowlisted values | 12 | only the dangerous argument counts; cleaning calls and allowlist ternaries clean the value |
| open redirect: a tainted value in a `Set-Cookie` header counted as the redirect target | 1 | same: target argument only |
| username enumeration on a change-password handler | 1 | requires a login context, ignores `oldPassword` messages |

**Second pass (same projects, after the fixes): 54 findings — 52 real or reasonable, 2 debatable, 0 false.**
The fixes also found things the first pass missed (the first pass could not see them):

| Newly found | Why it was missed |
|---|---|
| 3x path traversal in Juice Shop (`res.sendFile(path.resolve('logs/', file))`) | `res.sendFile` / `res.download` were not sinks |
| open redirect in Juice Shop (`res.redirect(toUrl)` behind a weak allowlist) | the request was destructured in the handler's parameters |
| request data in `({ body, file }: Request, res)` handlers, `GET(request, { params })`, Koa `ctx.query`, Fastify `request.query`, Hono `c.req.query()` | those forms were not sources |

Per project after the fixes: 0 findings on seven ordinary projects (all previously noisy ones: 6 on ai-chatbot,
17 on chatbot-ui, 8 on nestjs-boilerplate, 5 on taxonomy, ...), 1 weak open redirect on chatbot-ui
(`redirect(origin + next)` can still change the host with `next = ".evil.com"`), 3 on Prisma examples (a real
hard-coded `APP_SECRET`, and two redirects to the `Referer` header), 50 on Juice Shop (22 real: 11 SQL injections
in routes and challenge snippets, 3 `sendFile` path traversals, SSRF, open redirect, 2 `$where` NoSQL injections,
2 unauthenticated admin routes, 2 hard-coded secrets; 28 reasonable: 18 id-param routes without an ownership
check, 6 state-changing routes without CSRF protection in a cookie-based app, 3 file paths guarded only by an
earlier lookup, 1 role read from the body).

**Read these numbers with the right caveat.** The second pass is measured on the same projects the fixes were
written from, so the 96% will not hold on code nobody has looked at; the first-pass figure (23%) is the honest
"unseen code" one, and what the fixes buy is that the categories behind it are gone. Four things are worth taking
away: (1) heuristic rules about *context* (CSRF, IDOR) were the noisiest and needed project-level knowledge, not
better pattern matching; (2) the dangerous-argument and cleaning-call refinements removed most of the SQL / path
false positives; (3) the biggest recall gains came from sources and sinks the rules did not know (destructured
parameters, `sendFile`), not from new analysis; (4) what the scanner still misses on Juice Shop (below) are
mostly stored/second-order flows.

**Still missed on Juice Shop** (known challenges): XXE through a project wrapper that sets libxml2 option flags
(`XML_PARSE_NOENT | ...`) instead of `noent: true`; `eval` of data read back from the database (second-order
code injection); unsafe `yaml.load` of an upload; JWT algorithm confusion; DOM-based and template XSS; weak
cryptography; and every flow that goes through a return value or a callback.

## Round 7: Supabase and Firebase rules

Two real Supabase projects were available in the corpus, both built with Row Level Security from the start
(Vercel's `nextjs-subscription-payments`, one init migration plus a `schema.sql`; `chatbot-ui`, 25 migrations).
That makes them a good test for false positives:

| Project | `supabase-rls` / `supabase-auth` findings | Verdict |
|---|---|---|
| nextjs-subscription-payments | 0 | correct: every table has RLS and owner policies |
| chatbot-ui | 8: 5 `SECURITY DEFINER` functions without `search_path`, 3 server-side `getSession()` calls (middleware, layout, login page) | all genuine and all things Supabase's own advisor / docs flag; none is a data-exposure hole |
| the other 13 projects | 0 | no Supabase / Firebase files |

No Firebase project was in the corpus, so `firebase-rules` is validated only against the unit tests and the
purpose-built fixtures (`examples/vulnerable-firebase-app`); expect a round on real Firebase repositories to teach
it things. Two false positives of *other* rules surfaced while building the Supabase fixture and were fixed with
regression tests: `Response.json({ secret: "..." })` was read as a hard-coded signing secret (now only inside calls
about sessions / tokens / auth), and `broken-access-control` did not know `supabase.auth.getUser()` is an access
check (it flagged every admin route of a Supabase app).

## Round 8: Firebase rules on six official projects

Six shallow, read-only clones of Firebase's own sample repositories — `friendlyeats-web`, `quickstart-js`,
`codelab-friendlychat-web`, `emulators-codelab`, `functions-samples`, `snippets-web` — 49 rules files (Firestore,
Storage, Realtime Database). These are tutorials, so many rules are *deliberately* loose to keep the lesson short;
the question is whether the scanner reads them correctly and ranks them sensibly.

**First pass: 33 findings, none wrong, and two misses.** 8 real (test-mode / `if true` / open Realtime Database
writes, several literally marked `TODO: Change these! Anyone can read or write`), 14 reasonable (anyone can write
the FCM-token collection; any signed-in user can edit or delete anyone's comment; a public `/users` node), 11 debatable
(an open read of a chat, or of all public images, that the sample documents as intentional). The two misses were
`allow write: if request.auth.uid != null;` on every Storage file (the same "any signed-in user" check, spelled
differently), so a rule that lets any user overwrite every file was not reported.

What changed, with tests:

| Change | Why |
|---|---|
| `request.auth.uid != null` counts as signed-in-only, like `request.auth != null` | the two misses above (now reported as critical) |
| open read of **all** Storage files is medium, not critical | public images are a normal setup; the same rule on Firestore stays critical |
| open reads of messages / chats are medium; of users, orders, payments, ... high | whether a chat is public is a design choice, personal data is not |
| Realtime Database root with `.read: true` and `.write: false` is high, not critical | public data with writes closed is exposure, not takeover (`.write: true` stays critical) |

**Second pass: 35 findings — 10 real, 14 reasonable, 11 debatable, 0 false**, with the two misses now found. The honest
reading: on well-written official samples the rules produce no wrong claims, and the debatable group is exactly where
a human has to decide "is this public on purpose?" — that is why those are medium and say so. These are tutorials; the
real test is vibe-coded Firebase apps, where open rules are far more often a mistake than a teaching shortcut, and
none was in the corpus.

## Round 9: 16 small vibe-coded Supabase / Firebase projects, first pass vs. second pass

The first test on the kind of project the scanner is for, not on official samples: small, recent, few-star GitHub
repositories built with Next.js / Vite / Express on Supabase or Firebase (several say "Lovable", "Bolt" or "Cursor"
in their README). Sixteen were picked from GitHub search results (ten on Supabase, six on Firebase) and cloned
read-only; nothing was installed or run. Every finding was checked against the real code BEFORE any rule was
changed, so the first-pass number is honest.

**First pass: 118 findings, 24 real or reasonable (20%), 94 false (80%).**

| Source of the false findings | Count | Why |
|---|---|---|
| `idor` | 61 | a catalogue (countries, brands, categories) behind `checkRole(['Admin'])` (52); the ownership check lives in the controller, not in the route file (8); a local `authorize()` helper that checks the session (1) |
| `csrf` | 20 | a `verifyCsrf` middleware registered once in `app.ts` (5); the API authenticates with the `Authorization` header and `cookie-session` is installed but never used (14); a Firebase-only app (1) |
| `hardcoded-secret` | 8 | the Firebase web `apiKey` (2); `includes("-----BEGIN PRIVATE KEY-----")`, a format check, reported twice as a leaked private key (2); passwords in a test script `test-suite.ts` (3); `DEV_ONLY_JWT_SECRET`, a development fallback the app refuses to use in production (1) |
| `supabase-auth` | 4 | `getSession()` in a hook, a context and a client-side lib of single-page apps: it is the normal call in the browser |
| `broken-access-control` | 1 | an `/internal/` route protected by a secret header compared with `timingSafeEqual` |

It also **missed** the worst thing in the corpus: one disaster-response app (`tablero-respuesta-ve`) has Firestore
rules with no `request.auth` anywhere. Anyone on the internet can read volunteers' phone numbers and national ID
numbers, change the status of every report, and overwrite the bank account shown to donors. The old rules only knew
`if true`, "signed in only" and collections whose name sounds private. A second app (`theswtch`) hid "signed in only"
behind a helper function `ok()`.

What changed (each with a regression test in `round9.test.ts`, `backend.test.ts`, `hardcoded-secret.test.ts`):

- `firebase-rules`: a write whose condition never mentions `request.auth` is reported (the shape of the data is not
  an access check); a public read is reported when the fields it holds are personal (phone, ID, e-mail, bank...),
  whatever the collection is called; zero-argument helper functions are expanded.
- `idor`: follows the route's handler into the controller file and into helpers it calls; skips routes behind an
  explicit role check.
- `csrf`: reads the whole project (a csrf mention anywhere, `Authorization` header without cookie use) and treats
  Firebase / Supabase-client apps as token-in-page auth.
- `hardcoded-secret`: Firebase web config, PEM headers without a body, `DEV_ONLY_*` names, test scripts.
- `supabase-auth`: `getSession()` only counts in server code.
- `broken-access-control`: a shared-secret check counts as an access check.
- `supabase-rls`: a project that only uses Supabase from a server (no anon key in the browser) gets medium / low
  instead of critical for a table without RLS.

**Second pass: 40 findings, all 40 real or reasonable (checked against the code), 0 false.**

| Project | Findings | What they are |
|---|---|---|
| `tablero-respuesta-ve` (Firebase) | 11 | public writes without auth to `tasks`, `reports`, `volunteers`, `announcements`, `suggestions`, `visits` and `config` (donation bank details); public reads of phone / ID numbers |
| `endtimes-live` (Supabase) | 12 | role read from `user_metadata` in 3 policies; 2 API keys written as fallbacks next to `process.env`; views without `security_invoker`; `SECURITY DEFINER` functions without `search_path` |
| `LibraEase` (Express + Supabase) | 5 | four tables without RLS (medium: server-only app); distinct "user not found" / "wrong password" messages |
| `theswtch` (Firebase) | 5 | any signed-in user can write settings, tasks, links; any signed-in user can read every profile |
| `watchtower` (Supabase) | 4 | four tables created in migrations without RLS |
| `nextjs-supabase-saas-starter` x2 | 2 | `${origin}${next}` redirect: `next=@evil.example` makes `https://app@evil.example` |
| `shopkeeper-price-tracker` (Supabase) | 1 | a table created without RLS (a later migration protects a different table, `prices`) |

Five projects (`FleetEase`, `web3-sabi`, `me-controla-ai`, `PHC-Copilot`, a Lovable finance app) went from 79
findings to 0; three stayed at 0 (`App-treino-nutricao` has careful rules, `JBF-Lite-QR-Catalog` and one SaaS starter
have nothing to report). The six official Firebase repos of round 8 still give the same 35 findings, and the nine
projects of round 6 give the same results as before.

**Honest limits:** 16 projects is a small sample, chosen from search results rather than at random, and "all findings
correct" says nothing about what was missed (the first pass missed the most serious problem in the corpus, and a
second pass can too). The `idor` change trades recall for precision: a driver reading another driver's inspection
by id behind `checkRole(['Admin', 'Manager', 'Driver'])` is no longer reported.

## Round 10: return-value taint, Server Actions and four new rules, measured on the 25 projects already triaged

The new work was run on the 25 projects of rounds 6 and 9 (nine projects with the 56 findings triaged in round 6, 16 with
the 40 triaged in round 9) to see what it adds and, above all, what noise it adds. Nothing was tuned on a project and
then re-measured on the same one without saying so.

**The old rules did not change: 56 findings on the round-6 projects, 40 on the round-9 projects, the same as before.**

First pass of the new code, before any fix, produced three kinds of noise, all on projects where the old rules had been
quiet. Each was read against the real code:

| First-pass finding | Why it was wrong | Fix |
|---|---|---|
| `open-redirect` in a SaaS starter, via the return-value taint | `safeNext(searchParams.get("next"))` returns its parameter, but only after `next.startsWith("/")`. The helper validates | a helper that tests the value (`if (!ALLOWED.includes(v)) return ...`, a ternary whose condition calls `startsWith` / `includes` / `test`) is not followed; names such as `safe*`, `verify*`, `check*` are not followed |
| 2 `path-traversal` in juice-shop | `tokens.get(token)` returns `token ? table[token] : undefined`: the **condition** `token ?` was counted as carrying the value | conditions, comparisons (`===`, `<`, `in`) and negations no longer carry a value |
| 7 `broken-access-control` on Server Actions in two Supabase starters | the action delegates the check to `getOrgContext()`, which is `cache(async () => ...)`, and the wrapper hid the function; and `supabase.from("projects").delete()` through a cookie-bound client is protected by Row Level Security | `cache` / `asyncHandler` wrappers resolve to the wrapped function; a Supabase client acting as the caller is not reported (RLS is the control, the `supabase-rls` rule reads the policies) |
| 1 `insecure-jwt` in juice-shop | `jwt.decode(security.authenticatedUsers.tokenOf(user))` reads a token the **server** holds | `decode` is reported only when its argument comes from the request |

**After those fixes: 6 new findings on 25 projects, all real.** `missing-rate-limit` on a fleet app whose `/login` compares a
password with no limiter anywhere; 2 `insecure-jwt` (`sign({ userId }, APP_SECRET)` with no expiry, in a Prisma example
app); 3 `broken-access-control` on Server Actions of Prisma's own example apps (`createPost`, `addPost`, `addVotes`:
anyone can post and vote; examples, but the claim is accurate). No `insecure-cors` and no `exposed-files` finding in any
of the 25 projects, so those two rules are **tested on fixtures only**: nothing in this corpus says how often they fire
on real code, and nothing says they miss anything either. Return-value taint added no finding on these projects; its
precision is checked by the regression tests (`return-taint.test.ts`), its recall is not measured.

## Round 11: SvelteKit, Remix, Nuxt, tRPC, Hono and four new rules, on 24 projects not seen before (+ NodeGoat)

The 25 projects below (24 new ones and NodeGoat) were picked from GitHub topic searches (`sveltekit`, `remix`, `trpc`, `hono`, `nuxt3`, `stripe-webhooks`,
`lemonsqueezy`), small (under 12 MB), recently pushed, few stars: the kind of code the scanner is for. Read-only shallow clones,
nothing installed or run. OWASP NodeGoat was added as the known-vulnerable reference.

**First pass** (before any tuning), 24 projects: **31 findings, 11 real (35%)**. The 20 false positives:

| Cause | Count | Fix |
|---|---|---|
| Seed / fixture files with made-up passwords and a demo SSH key (`seed/login-record-seed.ts`, `devSeed.ts`) | 11 | credentials judged by name are skipped in seed / fixture / mock / story files (the file's own name and two folders above it only); provider-format tokens are still reported there |
| `/regex/.exec(file)` taken for `child_process.exec` | 1 (+1 more through it) | a regex literal or a regex-named receiver is not a shell |
| `fetch(`https://oeis.org/${param}`)`: scheme and host fixed, only the path is the caller's | 2 | not SSRF when the host is written in the code |
| `new Response(request.body)`, used to read a stream and sent as `text/plain` anyway | 2 | `new Response(x)` is XSS only when the options declare HTML; `c.html()` (Hono) added as a sink |
| `options.scopes.map((s) => escapeHtml(s)).join("")` carried taint through the callback | 1 | a callback that cleans each element (escape / sanitize / encodeURI / Number...) cleans the result |
| A schema written as a string (`'v.pipe(v.string(), v.minLength(1))'`) taken for a secret | 2 | a value that is a call expression is code, not a credential |

Left as they are: `pinCatalogAlbum(..., apple_music_id)` (a zod-validated number reaching a fixed host; the scanner cannot see types) and a
dev smoke script that reflects a query value into an `.m3u8` playlist.

**Second pass: 13 findings in the 24 projects, 11 real (85%).** The real ones: `getSession()` trusted on the server in a SvelteKit
hook (Supabase's advice at the time, now outdated), an unchecked `next` redirect in two Supabase auth callbacks (`${origin}${next}`
is open to `@evil.com`), a user-supplied `source_url` fetched without a host check, a reflected error in a local OAuth callback, and
six Prisma-migration tables in a project that also uses Supabase (no RLS).

**New framework support, measured:** `examples/vulnerable-frameworks` (a fixture with the same mistakes in each style) is found in full,
and its safe twins are not reported (`frameworks.test.ts`). On real code the new access-control check reported 8 handlers in Prisma's
own example apps (Nuxt `server/routes/*`, a React Router `action`, tRPC `publicProcedure.mutation`s): all accurate, none of them check
anyone, they are demos. **No** SvelteKit / Remix / Nuxt / tRPC handler in the 24 new projects was reported wrongly; but most of them have
no mutation handler at all, so this is a weak test of precision for those frameworks, not proof.

**New rules on real code** (every project downloaded so far, rounds 6-11): `mass-assignment` 6 findings (3 `create(req.body)` / `update(id, req.body)` in a
real fleet-management app and 3 in Prisma's deployment examples: all accurate), `insecure-token-storage` 9 (a real app, Juice Shop; the
`__session` cookie set from JavaScript in Firebase's own sample is the documented pattern but still readable by scripts),
`prototype-pollution` 2 (Juice Shop: `solves[key][mode] = verdict` with a request-chosen key), `webhook-signature` 0 (its one first-pass
hit was a smoke-test script that lists Stripe event names: the handler test was tightened). Only one project in the corpus has a payment
webhook, so this rule's recall on real code is **not measured**; it is tested on fixtures.

**Re-run of the earlier corpora** after the precision changes: round 9's 16 projects: 41 findings (unchanged); round 6/8's: no old finding
lost; the only increase is the 8 access-control findings above.

**NodeGoat** (deliberately vulnerable): 13 findings, all in the code it is meant to have: 3 `eval(req.body.*)`, the `$where` NoSQL injection, the
open redirect, the SSRF through `needle.get(req.query.url + ...)` (**found now: `needle`, `superagent`, `ky`, `undici` were not known HTTP
clients**), username enumeration, no rate limit on login, CSRF, and 4 hard-coded secrets. Still missed, as listed below: the IDOR on
`/allocations/:userId` (the `isLoggedIn` middleware reads `req.session`, which the rule takes as proof of an ownership check; a comment
saying `req.session` used to count too, which is fixed), `/benefits` without an admin check, XSS through templates, ReDoS, cookie flags.

**Cost:** the scan is dominated by the data-flow rules, each of which walks every function once; four more rules added about 7%.
The slowest project (322 files, one 150 KB route file) takes 25 s in total, as before. Not optimised yet: the rules do not share the
work of finding request sources.

## Round 12: Python and PHP, on 23 small real projects + DVWA and pygoat

The Python (Flask, FastAPI, Django) and PHP (scripts, Laravel) analyzers are new, so this is their first contact with code they were not written
against: 23 small, recent projects from GitHub topic searches (`flask`, `fastapi`, `django`, `laravel`, `php`; read-only shallow clones, nothing
installed or run), plus two deliberately vulnerable applications as the reference for what is found: **DVWA** (PHP) and **pygoat** (Django).

**First pass** (before tuning), 23 real projects: **44 findings, about 30 of them real (about two thirds)**. What was wrong:

| Cause | Count | Fix |
|---|---|---|
| Laravel validation rules read as passwords (`'password' => 'required\|string\|min:8\|confirmed'`) | 8 | a `rule\|rule:arg` list is not a credential |
| Django's `tests.py` and a Laravel seeder with made-up passwords | 4 | `tests.py` / `test.py` are test files; `seeders`, `factories` join the seed / fixture folders |
| `redirect(f"{reverse('home')}?open_modal={id}")`: the target starts with a path of the site | 1 | a redirect whose target begins with a same-site path (`/x`, `reverse()`, `url_for()`, `header("Location: /x")`) is not open |
| `DEBUG = True` in `settings/dev.py` and a tests settings file | 2 | judged by the file's own name and two folders above it (the scanner does not look further up: a project in a folder called `test` is still scanned) |
| 5 admin-panel JavaScript bundles (300-900 KB, not named `.min.js`) took 15 s each: the scan of one project took **76 s** | (time) | a file whose lines average over 300 characters is skipped with a visible note: the same project takes **4.7 s** |

A mistake of the engine itself, found by DVWA: `$_FILES["f"]["tmp_name"]` is a path PHP chose, not the caller's; only the name and the type are. It was treated as input.

**After the fixes: 25 findings in the 23 projects.** Accurate: `pickle.loads` of a form field in a metadata review route (remote code execution; the best find of the round),
12 path-traversal findings in a file-sharing app (a file manager whose paths come from requests), `SECRET_KEY` and `DEBUG = True` in Django settings that still carry the
`django-insecure-` placeholder (3 projects), a JWT secret with a literal default in a pydantic settings class, `app.run(debug=True)`, a SQL schema inside a served
`static/` folder, two `localStorage` tokens. Uncertain: 3 passwords in a script that generates a Postman collection (test credentials of a dev tool, probably).

**DVWA** (PHP, deliberately vulnerable): 43 findings. Found: SQL injection (3 of 3 modules at the low level and the blind variant), command injection (every level), open redirect,
the JSONP reflected value, hard-coded tokens, `phpinfo()`, 14 file-path findings. **Missed:** reflected / stored / DOM XSS, file inclusion, file upload, CSRF, weak session ids,
captcha, JavaScript: about half of its vulnerability families. The reason for the two biggest (XSS, file inclusion) is the same: DVWA builds the output in one file
(`$html .= ...`) and prints it (or `include`s the chosen file) in another, and the PHP analysis does not follow a value across files. False positives in the same run: the
"impossible" level's `shell_exec('ping ' . $target)`, where `$target` was checked with `is_numeric` first (the scanner has no notion of a validating `if`), and `PHP_SELF` in a redirect helper.

**pygoat** (Django, deliberately vulnerable): the SQL injections through `raw()`, `eval`, `yaml.load`, `pickle.loads`, SSRF with `requests.get`, a file opened from a request value, and
a command run through a helper, plus 25 `@csrf_exempt` views and the placeholder `SECRET_KEY`. Not found: its template-based XSS (HTML templates are not read) and access-control labs.

**Limits shown by this round** (also in docs/rules.md): data flow stays inside one file (plus helpers in that file), no template languages (Jinja, Django templates, Blade, Twig),
no validation-by-`if`, no mass-assignment rule for Python, no JWT / CSRF rules for PHP. 23 projects is a small sample and most of them have few request handlers, so precision
here is **less well measured than for JavaScript**; the numbers above describe this sample, not the languages.

## Round 13: Python and PHP, second pass: across files, value checks, templates

Same 25 projects as round 12 (they are the only measurement there is for these two languages), after four improvements: data flow across files, value checks,
template-aware XSS, and the remaining rules (Python mass assignment, PHP JWT / CSRF).

| | Round 12 (final) | Round 13 |
|---|---|---|
| Findings in the 23 real projects | 25 | 22 |
| DVWA (PHP, intentionally vulnerable) | 43 | 41 |
| pygoat (Django, intentionally vulnerable) | 49 | 51 |
| Scan time of the two largest projects (459 and 1105 files) | 4.7 s / 12 s | 5.3 s / 18 s |

What changed, finding by finding:

- **Removed, correctly:** DVWA's "impossible" command injection (the address is checked with `is_numeric` on every octet), and 5 findings in a file-sharing app where a user name had been
  validated with an anchored `re.match` and `return 400` before it reached `os.makedirs` (the checks above). One real vulnerability briefly disappeared with the checks and was
  restored: DVWA's API `exec("ping " . $target)` sits under `if (array_key_exists("target", $input))`, and a check that a key EXISTS says nothing about its value.
- **Added, correctly:** two XSS in pygoat through its templates (`xss_lab.html` prints the variable with `|safe`), the wildcard CSRF exception in a Laravel 11 `bootstrap/app.php`
  (`validateCsrfTokens(except: ['*'])`), one more path-traversal in the file-sharing app.
- **False positives found and fixed on the way:** a Blade `<form>` whose `@csrf` is in an `@include`d partial (not judged now); a controller `show(Training $training)` read as user text
  (Laravel loads that model by the URL's id: class-typed parameters are records, not input); `{!! nl2br(e(strip_tags($x))) !!}` flagged as a raw print (escaped inside).
- **No new finding of the cross-file kind in these 25 projects.** Their database code is in the same file as the handler, or in Eloquent models, which parameterize. The cross-file
  flow is therefore tested only on fixtures (`examples/vulnerable-python-app/app/`, `examples/vulnerable-php-app/`: a helper in another module, a module alias, an imported
  class's method, a global PHP function, a static method, an injected service, two and three calls deep) and on synthetic projects (cyclic calls do not loop): **its recall and precision
  on real code are not measured.** The cost on the 1105-file Laravel project is about 6 s more (reading the names of all functions once).
- **Still missed in DVWA:** file upload, weak session ids, captcha, JavaScript. (Reflected XSS and file inclusion through `include` were missed here and are found since round 15.)

**Bundles.** Minified or bundled files without `.min` in the name are skipped with a note (round 12), which is what keeps the larger projects fast.

## Round 14: layered Python and PHP projects (repository / service / use-case pattern)

Round 13 added data flow across files, but its sample had no layered code to test it on. This round took **27 small recent projects that are organised in layers** (FastAPI with
use cases, Flask and Django with service modules, Laravel and Slim with repositories), found by searching GitHub for the repository-pattern, clean-architecture and service-layer
topics. Read-only shallow clones, nothing installed or run.

| | first pass | after the fixes |
|---|---|---|
| findings | 39 | 21 |
| false positives | 20 | 2 |
| uncertain | 3 | 3 |

**What was wrong (18 of the 20 false positives came from four causes; the other 2 remain):**

- **`use_case.execute(command)` is not SQL (7).** The SQL sink matched any call ending in `.execute`. Clean-architecture FastAPI projects name their use-case objects `.execute(...)`, so every route
  that passed a request field to one was reported as SQL injection (`container.import_products.execute(file)`, `GetMyProfileUseCase(service).execute(actor)`). Now `execute` / `executemany` counts as a
  database call only when the receiver looks like a database handle (`cursor`, `conn`, `db`, `session`, `engine`, ...) or the argument is plainly SQL text being built (a string, an f-string,
  `+`, `%`, `.format()`, `text(...)`).
- **Demo logins (5).** `{ email: "alice@example.com", password: "Alice123!" }` in a login page, and `json_schema_extra` examples in Pydantic schemas. A password on a line that names an
  `@example.com` / `@test.com` / `@localhost` address is now a demo login.
- **Stubs and development fallbacks (4).** `access_token="stub-access-token-123"` in a stub provider, `_DEV_SECRET = "dev-only-secret-..."`, `SECRET_KEY = "django-insecure-local-dev-only"` inside an
  `if IS_DEVELOPMENT` branch, and a password in `scripts/e2e_*.py`. `dev-only` and `stub-` are placeholder words now, and `e2e` files and folders are fixtures.
- **A redirect whose host is configuration (1).** `redirect(f"{frontend_base_url}/book/{path}")`: the caller adds a path to a host that comes from settings. Names such as `base_url`,
  `site_url`, `frontend_url` count as a fixed host.

One deliberate non-change: `secret_key = "change-me-in-production"` is still reported. A default that is never replaced is a real hole, and the scanner says so.

**The 21 that remain**, triaged by hand: 16 real (debug mode on in 4 files, `phpinfo()` left in `public/`, a hard-coded JWT secret, basic-auth password and database URI in a Flask config, a faucet API key,
a default signing secret, the token in `localStorage`, two `$this->user->update($request->all(), $id)` mass assignments, `display_errors` on, two `Thumbs.db` files in `public/`), 3 uncertain
(Blade forms without `@csrf` in an EasyUI project that probably submits them by Ajax with a header token), 2 false (a Flask route `<filename>` joined to a directory: Flask's default converter
refuses a `/`, so the value cannot climb out of the directory; the scanner does not model converters for the path-traversal sink).

**Cross-file flow, honestly.** None of the 21 findings needed it. These 27 projects keep their queries behind ORMs or parameterised repositories, so the layered code produced no cross-file true
positives and no cross-file false positives either: the recall of the cross-file analysis on real code is still not measured. What this round did measure is the opposite side: the new
sink-by-name rule was the largest source of noise in layered code, and it is fixed. Corpus 6 (DVWA, pygoat and 23 others) gives exactly the same 114 findings before and after the fixes.

Speed: the slowest project (178 files, a Laravel app with vendored jQuery plugins) takes about 23 s, almost all of it in the JavaScript analyzers on non-minified third-party libraries under `public/`,
not in the Python or PHP engines.

## Round 15: variables shared through `include`, URL segments

Two known gaps from rounds 12–14, fixed and measured on the same corpora (no new downloads).

**PHP: `include` / `require` shares variables.** DVWA builds a page in two files: `source/low.php` sets `$html .= 'Hello ' . $_GET['name']`, `index.php` includes the chosen variant and prints `$html`.
The scanner now works out, for every file, which variables it leaves holding the caller's text at its end, and an `include` brings those into the including scope. The path is resolved from what the
code spells out: `include 'lib/db.php'` exactly, `require __DIR__ . "/source/{$level}.php"` as every file under `source/` (at most 12, two includes deep). Writing one key of an array
(`$page['body'] .= "…{$html}…"`) puts the text into the array, so the later `dvwaHtmlEcho($page)` is reported. A finding says which files set the variable.

| DVWA (`corpus6`) | before | after |
|---|---|---|
| findings | 41 | 50 |
| new | | 9: the include in `fi/index.php` (local file inclusion), reflected XSS in `xss_r`, `sqli`, `brute`, `csp`, `bac` (a cookie printed raw), `api`, `upload`, `view_source` |
| lost | | 0 |

All nine were checked by hand against the source: each is a real, intended DVWA bug. The other 24 projects of corpus 6 and the 27 of corpus 7 gain nothing and lose nothing from this change.
Scan time is unchanged (20 s for the 1105-file Laravel project).

**Python: a URL segment cannot climb out of a directory.** `@app.get("/<filename>")` (Flask) and `@app.get("/files/{name}")` (FastAPI) refuse a `/` in the placeholder, so `os.path.join(DIR, filename)` can not leave `DIR`.
Such a value is no longer reported for `path-traversal` (it still is for SQL, commands and the rest). `<path:name>`, `{name:path}`, query parameters and `unquote(name)` still are. The flask-openapi3 form
`def get(path: FileModel)` counts too. This removes the 2 false findings left in round 14 (corpus 7: 21 → 19, nothing else changed).

Not done: Django `path()` converters (they live in `urls.py`, not next to the view), and a lone `..` as the whole segment.

## Round 16: speed on copied libraries, Django URL converters, templates that extend others

Three changes measured on the corpora already triaged (rounds 9-15: 93 projects, no new downloads).

**Third-party libraries copied into `public/`.** JavaScript with a bundler's output at the top (`webpackBootstrap`) or with a library licence banner (`/*!`, `@license`,
"Released under the MIT license") in a folder of static files is skipped with a note. On the slowest project of round 14 (a Laravel app with 74 jQuery / EasyUI / lodash
files and a webpack `app.js` under `public/`) the scan went from **26 s to 1 s**. Those 75 files are the only ones the rule skips in all four corpora (checked by hand: every one
is a third-party library or the bundle), and the findings are identical in every corpus (46 / 25 / 123 / 19).

**Django URL converters.** A view's URL parameters are judged by the project's `urls.py`: `<int:pk>`, `<slug:s>`, `<uuid:u>` and `(?P<id>\d+)` carry nothing of the
caller's text, `<name>` / `<str:name>` is one segment (no "/": not path traversal), `<path:p>` is any text. The corpora have 17 routes with parameters (pygoat, HearWell,
CareerHub, ...); none of their findings depended on an `int` or `slug` parameter, so the counts do not move. The change is pinned by tests (function and class-based views).

**Templates that extend or include others, and Twig.** A value handed to `page.html` is now checked in the layout it extends and the partials it includes (Jinja, Django,
Blade), and `$this->render("x.html.twig", [...])` is read with `{{ x|raw }}` as Twig's unescaped print. No change in the corpora: their unescaped prints were already in the
rendered template itself (pygoat), or the values were not the caller's. Tests cover a `|safe` in an included part, `{!! !!}` in a Blade partial, and `|raw` in a Twig parent.

Still open: a variable renamed on the way into an include (`with a=b`), Django `register_converter` (a custom converter is treated as any text), and `include()` prefixes
(`path("users/<int:id>/", include(...))`: the prefix's parameters are not passed on to the included views).

## What the scanner still misses (false negatives)

After round 3, the remaining misses in the two deliberately vulnerable apps are
classes with no rule yet, or ones that need cross-file data flow:

- **XSS through templates** — only `res.send(...)`-style sinks are recognised
  (NodeGoat/dvna render user input through EJS/Handlebars-style templates)
- **Missing function-level access control** on a route that doesn't *look*
  privileged (NodeGoat's `/benefits`)
- **IDOR when the id isn't a route param** (dvna reads `req.query.id` / `req.body.id`)
- **Callbacks, values stored in object fields, DI containers**: the cross-file analysis follows data
  into functions and back out through their return value (`const q = buildQuery(x); db.query(q)`), but not
  through a callback or a field
- **ReDoS, insecure cookie/session settings, weak crypto** — no rules

The original plan's "false negatives < 10%" target is still **not met** for
real-world vulnerable code; it only holds within the classes covered.

## Known parser limitations (not fixable by switching grammar)

7 of 187 scanned files still report "syntax errors" (results for them may be
incomplete): generic tagged templates such as ``sql<User[]>`...` `` and some JSX
attributes in `.js` files fail in `tree-sitter-typescript@0.23.2` /
`tree-sitter-javascript@0.23.1`. Both are the latest published versions.
