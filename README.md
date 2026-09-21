# Security Testing Hub

[![CI](https://github.com/dam1r-dev/security-testing-hub/actions/workflows/ci.yml/badge.svg)](https://github.com/dam1r-dev/security-testing-hub/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

An open-source static analysis (SAST) scanner built for **"vibe coders"** —
people shipping Node.js/Express apps fast with AI coding assistants, who
don't always have time to review every line an LLM generates for injection
bugs. Point it at your project; it parses the real AST (via
[Tree-sitter](https://tree-sitter.github.io/tree-sitter/)) and flags
untrusted input flowing into dangerous sinks.

> 🇷🇺 Русская документация: [docs/README.ru.md](docs/README.ru.md)

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
| CSRF | [CWE-352](https://cwe.mitre.org/data/definitions/352.html) | route heuristic (no token check found) |

See [docs/rules.md](docs/rules.md) for how each rule works and its known
false-positive/false-negative tradeoffs.

## How it works

1. **Parse** — each `.js`/`.jsx`/`.ts`/`.tsx` file is parsed into a real AST
   with Tree-sitter (not regex).
2. **Taint-track** — for the four data-flow rules, the analyzer finds
   "source" expressions (`req.params`, `req.query`, `req.body`, ...),
   follows them through local variable assignments and template-literal
   interpolation **within the same function** (intra-procedural — see
   [Scope & limitations](#scope--limitations)), and checks whether a
   "sink" call (`db.query`, `res.send`, `exec`, `fs.readFile`, ...) uses
   the tainted value.
3. **Report** — findings come out as colored terminal text, JSON, or
   [SARIF](https://sarifweb.azurewebsites.net/) (drop straight into GitHub
   code scanning).

## Install

```bash
git clone https://github.com/dam1r-dev/security-testing-hub.git
cd security-testing-hub
npm install
npm run build
```

## Usage

```bash
# Scan a directory, human-readable output
npm run scan -- scan ./my-express-app

# JSON, for scripting
npm run scan -- scan ./my-express-app --format json

# SARIF, for GitHub code scanning / other SAST dashboards
npm run scan -- scan ./my-express-app --format sarif --out results.sarif

# CI gate: exit 1 if anything critical/high is found
npm run scan -- scan ./my-express-app --fail-on high
```

Try it against the bundled, deliberately-broken fixture app:

```bash
npm run scan -- scan examples/vulnerable-express-app
```

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
- **CSRF detection is heuristic**, not taint-based: it flags state-changing
  routes (`POST`/`PUT`/`DELETE`/`PATCH`) in files with no visible CSRF
  middleware/token check. It assumes cookie/session-based auth; pure
  bearer-token APIs aren't CSRF-exploitable and should be filtered out
  manually for now.

## Project layout

```
packages/
  scanner/   core: Tree-sitter parsing, taint analysis, analyzers, SARIF output
  cli/       `security-hub` command-line interface
examples/
  vulnerable-express-app/   deliberately vulnerable fixture app (do not deploy)
docs/        rule docs, dev plan, Russian docs
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
