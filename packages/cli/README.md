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

## Usage

```bash
security-hub scan ./my-app                       # human-readable, colored
security-hub scan ./my-app --format json          # for scripting
security-hub scan ./my-app --format sarif --out results.sarif   # GitHub code scanning
security-hub scan ./my-app --format html          # open security-report.html in a browser
security-hub scan ./my-app --fail-on high         # CI gate: exit 1 if anything critical/high found
```

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
