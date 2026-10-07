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

## What the scanner misses (false negatives)

On the two deliberately vulnerable apps the scanner found roughly a quarter to
a third of the planted bugs. The misses are mostly vulnerability *classes it has
no rule for yet*, not detection bugs inside the 11 rules it has:

- **Code injection** — `eval(req.body.x)` (NodeGoat), `mathjs.eval(req.body.x)` (dvna)
- **Open redirect** — `res.redirect(req.query.url)` (NodeGoat)
- **NoSQL injection** — user input in MongoDB `$where` / query objects (NodeGoat)
- **Insecure deserialization** — `node-serialize` `unserialize` (dvna)
- **XXE** — `libxmljs.parseXml(..., {noent: true})` (dvna)
- **XSS through templates** — only `res.send(...)`-style sinks are recognised
- **Missing function-level access control** on a route that doesn't *look*
  privileged (NodeGoat's `/benefits`)

The original plan's "false negatives < 10%" target is therefore **not met** for
real-world vulnerable code; it only holds within the classes covered.

## Known parser limitations (not fixable by switching grammar)

7 of 187 scanned files still report "syntax errors" (results for them may be
incomplete): generic tagged templates such as ``sql<User[]>`...` `` and some JSX
attributes in `.js` files fail in `tree-sitter-typescript@0.23.2` /
`tree-sitter-javascript@0.23.1`. Both are the latest published versions.
