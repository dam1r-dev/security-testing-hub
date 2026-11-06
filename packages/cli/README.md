# security-hub

Open-source security scanner for AI-assisted ("vibe coded") projects, where
the usual bugs slip in fast. 36 rules for **JavaScript, TypeScript, Python,
PHP, Go and Java** (Express, Next.js, SvelteKit, Remix, Nuxt, Flask, FastAPI, Django,
Laravel, Slim, net/http, gin, echo, fiber, chi, Spring, Servlets, JAX-RS): SQL / command / code injection, XSS, path traversal, SSRF,
open redirect, CSRF, IDOR and broken access control, leaked secrets, unsafe
Supabase and Firebase rules, JWT and CORS mistakes, and more.

A report says what it did *not* look at: files in languages without rules,
skipped bundles and libraries, files that did not parse. A scan that analysed
nothing is "not rated", never "100/100".

Full docs, rule reference, attack playbook (EN/RU/KK), and the scanner
engine's source live in the main repo:
**https://github.com/dam1r-dev/security-testing-hub**

## Install

```bash
npm install -g security-hub
# or, one-off, no install:
npx security-hub scan .
```

Don't like terminals? `security-hub ui` opens a local web interface (pick a
folder, click Scan, see the score and findings). It listens on `127.0.0.1` only —
your code never leaves your computer.

## Usage

```bash
security-hub scan ./my-app                       # human-readable, colored
security-hub scan ./my-app --format json          # for scripting
security-hub scan ./my-app --format sarif --out results.sarif   # GitHub code scanning
security-hub scan ./my-app --format html          # open security-report.html in a browser
security-hub scan ./my-app --fail-on high         # CI gate: exit 1 if anything critical/high found
security-hub scan ./my-app --ignore legacy/ --ignore "*.mock.js"   # skip paths (also reads .security-hub-ignore)
security-hub scan ./my-app --include-tests        # tests are skipped by default
security-hub scan ./my-app --changed-since origin/main   # report only files changed vs. a branch (whole project still scanned)
security-hub scan ./my-app --format markdown      # or: github (workflow annotations)
```

Hide a single finding you have reviewed with a comment on the flagged line or the line above:
`// security-hub-ignore` (all rules) or `// security-hub-ignore sql-injection -- reason`.
The report counts what was hidden. Details: the main repo's README.

Every scan includes a 0-100 score (green ≥80 / yellow 50-79 / red <50) —
see [docs/rules.md](https://github.com/dam1r-dev/security-testing-hub/blob/main/docs/rules.md#the-0-100-score)
for how it's computed.

## Disclaimer

Defensive use only: finding and fixing vulnerabilities in code you own or
are authorized to test. This is a heuristic scanner — expect both false
positives and false negatives; it's a helper, not a replacement for
security review.

## License

MIT
