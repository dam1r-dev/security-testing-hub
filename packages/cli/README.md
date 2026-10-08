# security-hub

Open-source SAST scanner CLI for Node.js/Express and Next.js App Router
apps — catches SQL injection, XSS, command injection, path traversal,
SSRF, CSRF, IDOR, broken access control, insecure file upload and
username enumeration. Built for AI-assisted ("vibe coded") projects,
where the usual injection bugs slip in fast.

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
