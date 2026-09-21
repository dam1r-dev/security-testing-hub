# Contributing

Thanks for considering a contribution — this is a solo-dev MVP built to a
public, honest dev plan (see [docs/dev-plan.md](docs/dev-plan.md)), so there's
plenty of room to help.

## Getting set up

```bash
git clone https://github.com/dam1r-dev/security-testing-hub.git
cd security-testing-hub
npm install
npm run build
npm test
```

## Where to start

- **New rules / analyzers:** look at `packages/scanner/src/analyzers/` — each
  one is a small, self-contained class. `sql-injection.ts` is the clearest
  example to copy from.
- **Reducing false positives:** the taint engine
  (`packages/scanner/src/taint/simple-taint.ts`) is intentionally simple
  (intra-procedural only, see [docs/rules.md](docs/rules.md) for known
  gaps per rule) — precision improvements there benefit every rule at once.
- **New sink patterns:** most rules are a `SOURCE_PATTERN`/`SINK_*_PATTERN`
  regex pair plus a predicate function — see any file in `src/analyzers/`.
- **Test fixtures:** `examples/vulnerable-express-app/` is a deliberately
  broken app used by the CLI test suite. Add a new vulnerable (and a
  corresponding safe) route there when you add a rule.

## Pull requests

1. Fork, branch off `main`.
2. Add tests for any new rule or bug fix — `npm test` must pass.
3. Run `npm run lint` and `npm run format`.
4. Open a PR describing the vulnerability class / bug and how you tested it.
   If you're adding a rule, include a link to the relevant CWE.

## Reporting a false positive / false negative

Open an issue with:
- The (minimal, reproducible) code snippet that was mis-scanned.
- What you expected vs. what the scanner reported.
- Which rule (`sql-injection`, `xss`, `command-injection`, `path-traversal`,
  `csrf`) is involved.

This project targets a 25-30% false-positive rate for v1 (see
[README.md](README.md#scope--limitations) for why) — so not every FP report
will be "fixed" immediately, but they're all useful data for tuning rules.

## Reporting a real vulnerability in this tool itself

Please don't open a public issue for a security bug in the scanner's own
code (e.g. something that lets a scanned project execute code during
scanning). Open a private [GitHub Security Advisory](https://github.com/dam1r-dev/security-testing-hub/security/advisories/new)
instead.
