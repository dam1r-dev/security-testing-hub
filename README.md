# Security Testing Hub

[![CI](https://github.com/dam1r-dev/security-testing-hub/actions/workflows/ci.yml/badge.svg)](https://github.com/dam1r-dev/security-testing-hub/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

An open-source static analysis (SAST) scanner built for **"vibe coders"** —
people shipping Node.js apps fast with AI coding assistants, who don't
always have time to review every line an LLM generates for injection bugs.
Point it at your project (Express **or** Next.js App Router); it parses the
real AST (via [Tree-sitter](https://tree-sitter.github.io/tree-sitter/)) and
flags untrusted input flowing into dangerous sinks.

> 🇷🇺 Русская документация: [docs/README.ru.md](docs/README.ru.md) ·
> 🇰🇿 Қазақша: [attack playbook](docs/attack-playbook.kk.md)

## Why this exists

AI pair-programmers are great at shipping features and often silently
reproduce the same handful of injection bugs (string-built SQL, unescaped
response bodies, `exec()` with interpolated input) because that's what's
common in training data. This tool is a fast, local pre-commit/CI check
tuned for exactly the patterns that show up in "vibe-coded" Express apps.

## What it detects (v1 / MVP)

| Vulnerability | CWE | Analyzer |
|---|---|---|
| SQL Injection | [CWE-89](https://cwe.mitre.org/data/definitions/89.html) | `db.query`/`execute`/`knex.raw` taint tracking |
| Cross-Site Scripting (reflected) | [CWE-79](https://cwe.mitre.org/data/definitions/79.html) | `res.send`/`write`/`end` taint tracking |
| OS Command Injection | [CWE-78](https://cwe.mitre.org/data/definitions/78.html) | `child_process.exec`/`execSync` taint tracking |
| Path Traversal | [CWE-22](https://cwe.mitre.org/data/definitions/22.html) | `fs.*` taint tracking |
| Server-Side Request Forgery (SSRF) | [CWE-918](https://cwe.mitre.org/data/definitions/918.html) | `fetch`/`axios`/`http(s)`/`request`/`got` taint tracking |
| CSRF | [CWE-352](https://cwe.mitre.org/data/definitions/352.html) | route heuristic (no token check found) |
| IDOR | [CWE-639](https://cwe.mitre.org/data/definitions/639.html) | route heuristic (id-like param, no ownership check) |
| Broken Access Control | [OWASP A01:2021](https://owasp.org/Top10/A01_2021-Broken_Access_Control/) | route heuristic (admin-looking path, no auth check) |
| Insecure Role Assignment | [CWE-639](https://cwe.mitre.org/data/definitions/639.html) | pattern match (role/admin field read from client input) |
| Insecure File Upload | [CWE-434](https://cwe.mitre.org/data/definitions/434.html) | pattern match (upload filter trusts Content-Type only) |
| Username Enumeration | [CWE-203](https://cwe.mitre.org/data/definitions/203.html) | pattern match (distinct login error messages) |

See [docs/rules.md](docs/rules.md) for how each rule works and its known
false-positive/false-negative tradeoffs, and
[docs/attack-playbook.md](docs/attack-playbook.md) for a hands-on guide to
testing every one of these (plus 2FA bypass and a couple of IDOR variants
that need manual testing — the scanner can't catch everything).

## How it works

1. **Parse** — each `.js`/`.jsx`/`.ts`/`.tsx` file is parsed into a real AST
   with Tree-sitter (not regex).
2. **Taint-track** — for the five data-flow rules, the analyzer finds
   "source" expressions — Express's `req.params`/`req.query`/`req.body`, or
   Next.js App Router's `request.nextUrl.searchParams.get(...)`,
   `request.cookies.get(...)`, `request.json()` (see
   [docs/rules.md](docs/rules.md#sources-shared-by-all-five-data-flow-rules))
   — follows them through local variable assignments and template-literal
   interpolation **within the same function** (intra-procedural — see
   [Scope & limitations](#scope--limitations)), and checks whether a
   "sink" call (`db.query`, `res.send`, `exec`, `fs.readFile`, ...) uses
   the tainted value.
3. **Report** — findings come out as colored terminal text, JSON, or
   [SARIF](https://sarifweb.azurewebsites.net/) (drop straight into GitHub
   code scanning).

## Install

```bash
# no install, one-off run:
npx security-hub scan .

# or install the CLI globally:
npm install -g security-hub
```

Working on the scanner itself, or want to run it from source:

```bash
git clone https://github.com/dam1r-dev/security-testing-hub.git
cd security-testing-hub
npm install
npm run build
```

## Usage

If you installed the CLI (`npm install -g security-hub` / `npx security-hub`),
drop the `npm run scan --` prefix below and just run `security-hub scan ...`
directly. Running from a source checkout uses the `npm run scan --` form
instead (it's just `node packages/cli/bin/security-hub.js` under the hood):

```bash
# Scan a directory, human-readable output
npm run scan -- scan ./my-express-app

# JSON, for scripting
npm run scan -- scan ./my-express-app --format json

# SARIF, for GitHub code scanning / other SAST dashboards
npm run scan -- scan ./my-express-app --format sarif --out results.sarif

# HTML report you can open in a browser — a colored 0-100 score, severity
# breakdown, and a filterable findings list. Defaults to security-report.html.
npm run scan -- scan ./my-express-app --format html

# CI gate: exit 1 if anything critical/high is found
npm run scan -- scan ./my-express-app --fail-on high
```

Every format includes a **0-100 score** (also shown as a colored line at the
end of `text` output): 100 minus a penalty per finding, weighted by severity
*and* by the rule's own confidence (a low-confidence heuristic hit costs less
than a taint-tracked, high-confidence one). Green ≥80, yellow 50-79, red
<50. It's a skimmable signal for "did this get better or worse", not a
certification — see [docs/rules.md](docs/rules.md) for what each rule can
get wrong. The math lives in `packages/scanner/src/output/score.ts`.

Try it against the bundled, deliberately-broken fixture apps:

```bash
npm run scan -- scan examples/vulnerable-express-app
npm run scan -- scan examples/vulnerable-nextjs-app
```

## Hands-on labs

Beyond static scanning, `labs/` has runnable Docker labs — a real vulnerable
app you exploit for real, not just a scanner finding to read.

```bash
npm run lab:sql-injection:up      # starts the lab on localhost:3300
# ... follow labs/sql-injection/README.md to exploit it ...
npm run lab:sql-injection:down    # stop and clean up

# or let the CLI drive it:
node packages/cli/bin/security-hub.js lab sql-injection
```

`npm run lab:sql-injection:e2e` runs the whole thing non-interactively: it
proves the vulnerable version leaks the flag via SQL injection, then proves
the parameterized-query fix actually closes it — the same check CI runs on
every push. Currently just SQL Injection; more labs (XSS, CSRF, ...) are a
post-MVP goal (see [docs/dev-plan.md](docs/dev-plan.md)).

## Scope & limitations

This is a v1 MVP, built to a **realistic** plan (see
[docs/dev-plan.md](docs/dev-plan.md)) rather than an idealized one:

- **JavaScript/TypeScript only.** Python and PHP support are a post-MVP
  goal (would need separate Tree-sitter grammars and per-language rules).
- **Intra-procedural taint analysis.** Taint is tracked within a single
  function body. If tainted input passes through a helper function
  (`sanitize(req.params.id)` in another file, or even a few lines up in the
  same file as a separate function), this version won't follow it there.
  Inter-procedural tracking is a v2 goal.
- **Target false-positive rate: 25–30%**, false-negative rate: <10%. For
  comparison, Snyk sits around 15–20% FP and SonarQube around 20–30% FP —
  a v1 tool from a solo dev landing in that range is an honest result, not
  a bug. Expect to triage findings, not treat every one as gospel.
- **CSRF, IDOR, Broken Access Control, Insecure Role Assignment, Insecure
  File Upload and Username Enumeration are heuristic/pattern checks, not
  taint-based** — each is documented in [docs/rules.md](docs/rules.md)
  with its specific known false-positive shapes. CSRF, for example, assumes
  cookie/session-based auth; pure bearer-token APIs aren't CSRF-exploitable
  and should be filtered out manually for now.
- **Two attack classes have no rule at all**: 2FA bypass (needs modeling
  session/request-flow state) and detecting a password field leaked in an
  API response body (needs modeling response shapes). Both are documented
  as manual-testing checklist items in
  [docs/attack-playbook.md](docs/attack-playbook.md).
- **Next.js dynamic route segments** (the `{ params }` second handler
  argument, e.g. `export async function GET(request, { params })`) aren't
  recognized as a taint source yet — `params` alone is too generic a name to
  match safely without more context. `searchParams`/cookies/body readers are covered.
- **`csrf`/`idor`/`broken-access-control` now understand Next.js App
  Router too** — a route's path comes from its folder structure
  (`app/api/accounts/[accountId]/route.ts`, including route groups like
  `(admin)`), not a string literal, and `idor`/`broken-access-control`
  recognize common Next.js session helpers (`getServerSession`, `auth()`,
  `currentUser()`) as ownership/auth evidence. `broken-access-control` also
  checks for a project-root `middleware.ts` mentioning an auth check before
  flagging — Next.js commonly centralizes access control there instead of
  per-route — but can't verify its `matcher` actually covers the specific
  route (that needs evaluating Next.js's matcher syntax, out of scope for
  v1), so it can still miss a route that middleware *should* cover but
  doesn't. `insecure-role-assignment`/`insecure-file-upload`/
  `username-enumeration` are still Express-pattern-only.

## Project layout

```
packages/
  scanner/   core: Tree-sitter parsing, taint analysis, analyzers, SARIF/HTML/score output
  cli/       `security-hub` command-line interface
examples/
  vulnerable-express-app/   deliberately vulnerable Express fixture app (do not deploy)
  vulnerable-nextjs-app/    same idea, Next.js App Router style (do not deploy)
labs/
  sql-injection/   runnable Docker lab: exploit it, then verify the fix
docs/        rule docs, dev plan, attack playbook (EN/RU/KK)
```

## Contributing

Contributions welcome — see [CONTRIBUTING.md](CONTRIBUTING.md). This project
follows a [Code of Conduct](CODE_OF_CONDUCT.md).

## Disclaimer

This tool is for **defensive** use: finding and fixing vulnerabilities in
code you own or are authorized to test. Findings can include false
positives and false negatives — it is a helper, not a replacement for
security review. Only scan and test applications you have permission to
assess.

## License

[MIT](LICENSE)
