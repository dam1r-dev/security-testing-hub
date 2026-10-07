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

## What the scanner still misses (false negatives)

After round 3, the remaining misses in the two deliberately vulnerable apps are
classes with no rule yet, or ones that need cross-file data flow:

- **XSS through templates** — only `res.send(...)`-style sinks are recognised
  (NodeGoat/dvna render user input through EJS/Handlebars-style templates)
- **Missing function-level access control** on a route that doesn't *look*
  privileged (NodeGoat's `/benefits`)
- **IDOR when the id isn't a route param** (dvna reads `req.query.id` / `req.body.id`)
- **Data returned from a function** (`const q = buildQuery(x); db.query(q)`), callbacks,
  values stored in object fields, DI containers: the cross-file analysis follows data
  *into* functions, not back out of them
- **ReDoS, insecure cookie/session settings, weak crypto** — no rules

The original plan's "false negatives < 10%" target is still **not met** for
real-world vulnerable code; it only holds within the classes covered.

## Known parser limitations (not fixable by switching grammar)

7 of 187 scanned files still report "syntax errors" (results for them may be
incomplete): generic tagged templates such as ``sql<User[]>`...` `` and some JSX
attributes in `.js` files fail in `tree-sitter-typescript@0.23.2` /
`tree-sitter-javascript@0.23.1`. Both are the latest published versions.
