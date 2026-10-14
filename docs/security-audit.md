# Security audit of Security Testing Hub itself

A scanner reads code written by somebody else and can change files in it, so it is a target. This is a review of the
project's own security, done on 2026-10-14 against `main` after the 0.5.0 release. Everything below was checked by
running it, not by reading it: the findings with a number were reproduced before they were fixed, and each fix has a
regression test.

## Method

- The project scanned with itself (`security-hub scan packages`), plus the scripts, the action and the workflows read by hand.
- `npm audit` for the dependencies; the full git history searched for secret-shaped strings; every tracked file checked
  for hidden and bidirectional Unicode characters ("Trojan Source"); the contents of both npm packages listed.
- Hostile inputs fed to the scanner: 17 crafted files up to 2 MB (unbalanced quotes, 400 000-term expressions, 300 000
  functions, 40 000 "secrets", deep nesting), each in its own process with a time limit.
- The local web server, the GitHub Action, the workflows and the repository settings read against what an attacker
  who controls the scanned project (or a pull request) could do.

## Findings and what was done

| # | Finding | Severity | Status |
|---|---|---|---|
| 1 | **A crafted file crashed the whole scan.** A 400 000-term `1+1+1+...`, a 100 000-link member chain, 5 000 nested parentheses made the recursive tree walk overflow the stack; the error escaped `scanSource` and ended the scan (and a CI job) | high (availability) | fixed: iterative tree walk; every check runs in its own guard, so one failing check costs a note on that file, not the scan |
| 2 | **A crafted file hung the scan.** 1 MB of unbalanced quotes kept the native parser busy for over 200 s; 40 000 properties that look like secrets made one check quadratic (over 60 s) | high (availability) | fixed: 20 s parse limit, 15 s analysis budget per file (checked in the tree walk and in the taint loops), a cap of 500 secret findings per file, per-object caching. The worst case in the 17-file test is now about 20 s per hostile file, with the rest of the scan unaffected |
| 3 | **The local web interface handed its token to anyone on the machine.** The per-run token was inside the page served at `/`, so another user or program on the same computer could fetch the page, read the token and drive `/api/browse` and `/api/scan` with the victim's file permissions | medium (multi-user machines) | fixed: the token travels in the link's `#fragment` (never sent to a server), the page strips it from the address bar, and the page itself contains no token |
| 4 | **"Fix with AI" prompts carried untrusted text.** A snippet, a message or a file name copied from the scanned project (an attacker's pull request) ends up in a prompt that people paste into assistants that can edit files and run commands: indirect prompt injection, including hidden characters such as the Unicode tag block | medium | fixed: every prompt says up front that the copied text is untrusted data and must not be followed; control, zero-width, bidirectional and tag characters are removed from everything taken from the project |
| 5 | **`git` ran inside the scanned folder with that folder's own config.** `core.fsmonitor` is a command git runs on `status` / `diff`; a folder that carries a hostile `.git/config` (an unpacked archive) could run it. Reproduced: plain `git status` ran the planted command | low-medium | fixed: every git call switches fsmonitor off and does not touch the repository (no index refresh, no locks, no prompts) |
| 6 | **`security-hub fix --write` could write through a symbolic link** (`.env` pointing at another file) and created `.env` readable by everyone; `.security-hub.bak` backups of files that held secrets could be committed by the next `git add .` | low-medium | fixed: refuses symbolic links and changes nothing in that case, new `.env` is `0600`, backups are added to `.gitignore` |
| 7 | **The vulnerable SQL-injection lab was published on all network interfaces** (`"3300:3000"`) while its README said it runs only on localhost; it also ran as root | medium | fixed: `127.0.0.1:3300:3000`, runs as the `node` user |
| 8 | **False positives of the new `exposed-files` rule on this project's own source**: the words `express.static(".")` in a message, and files called `*secret*.ts` | low | fixed: the rule reads the syntax tree instead of text, and only data formats count as credential files |
| 9 | **The site allowed any inline script** (`script-src 'unsafe-inline'`) | low | fixed: only the one inline script, by SHA-256 hash; a test fails when the hash is out of date (`node scripts/update-site-csp.js`) |
| 10 | **CI workflow had no explicit permissions**; the release job installed `npm@latest` while holding publish rights | low | fixed: `permissions: contents: read`; `npm@11` |
| 11 | **35 vulnerable development dependencies** (jest 29 chain: 1 critical in `handlebars`, 29 high) | low (not shipped) | fixed what could be fixed: jest 30, `npm audit fix` -> 20 moderate left in the jest toolchain, 0 critical, 0 high. **0 vulnerabilities in what is published** (`npm audit --omit=dev`) |
| 12 | No `SECURITY.md`, no Dependabot | info | added |
| 13 | Found along the way, not a vulnerability: **the native parser could only be loaded once per process.** A second module registry that loaded the tree-sitter addon again (every test file in a test runner, or a host application that holds two copies of the package) got trees without a root: random "Cannot read properties of undefined" failures. The test suite had hidden it with `maxWorkers: 32` (one process per test file) and started failing when the 33rd file was added | info | fixed at the root: the parser is loaded once per process and shared (`src/parsers/ast-parser.ts`); the whole suite now also passes in a single process (`jest --runInBand`) |

## Checked and found fine

- **No secrets anywhere**: every commit on every branch has no token, key or password-shaped string except
  AWS's documented example key `AKIAIOSFODNN7EXAMPLE` in a test. GitHub secret scanning and push protection are on.
- **No hidden characters** in any tracked source file.
- **The published packages**: no install scripts, no files outside `dist/` and `bin/`, no absolute local paths, the CLI
  depends on the scanner by an exact version. Releases use npm Trusted Publishing (OIDC): no stored npm token.
- **The GitHub Action**: inputs reach the script through environment variables, never through the script text; the
  version input is validated against a strict pattern; every subprocess uses an argument array (no shell); the PR
  comment is only rewritten when it was posted by a bot; findings and comments are escaped (markdown, HTML, workflow
  commands); fork pull requests get a read-only token and the check degrades to annotations.
- **The workflows**: `pull_request`, never `pull_request_target`; least-privilege `permissions`; no repository secrets.
- **The local web interface**: loopback only, `Host` check (DNS rebinding), token compared in constant time, POST
  origin check, 16 KB body limit, strict CSP, scan data inserted with `textContent` only.
- **File traversal**: the scanner never follows symbolic links (links are neither files nor directories to it).
- **The HTML report**: every value from the scanned code is HTML-escaped, including attributes.

## Recommended, needs the owner (repository settings)

- **Enable Dependabot alerts and security updates** (Settings -> Code security). They are off; `.github/dependabot.yml` is
  in place for version updates.
- **Enable private vulnerability reporting** (same page), which `SECURITY.md` points to; it is off.
- **Protect `main`**: a ruleset that blocks force pushes and deletion of the branch (no branch protection exists today).
- Optionally turn on **CodeQL** default setup, and pin third-party actions by commit SHA once any are added (today all
  workflow actions are GitHub's own, referenced by major version).
- In security-sensitive pipelines pin the Action's `version:` input to an exact release instead of `latest`.

## What a scan still cannot promise

The analysis limits are documented in `docs/rules.md` and `docs/validation.md`: heuristic rules have false positives and
false negatives, and a file that is too complex to finish in the time budget is reported as incomplete, not as clean.
