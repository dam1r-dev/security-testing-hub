# Changelog

Both packages (`security-hub-scanner`, `security-hub`) are released together at the same version.

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
