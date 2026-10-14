# Security policy

Security Testing Hub reads code that somebody else wrote (a project you downloaded, a pull request from a stranger) and
can change files in it (`security-hub fix --write`), so its own security matters. Thank you for taking it seriously.

## Reporting a vulnerability

Please **do not open a public issue** for a security problem. Use GitHub's private reporting instead:
**Security -> Report a vulnerability** on https://github.com/dam1r-dev/security-testing-hub/security/advisories/new

Include what you found, how to reproduce it (a small project or file that triggers it is ideal) and what you think the
impact is. You can expect a first answer within a few days. A fix is released as a new version of both packages
(`security-hub` and `security-hub-scanner`), and the advisory credits you if you wish.

## Supported versions

Only the latest release of both packages receives security fixes (the packages are released together, always at the
same version). Update with `npm install -g security-hub@latest` or `npx security-hub@latest`.

## What is in scope

- Running a scan, `fix`, `ui` or the GitHub Action on an untrusted project makes something happen that it should not:
  code execution, a file written or read outside the project, a hang or crash caused by a crafted file, a secret
  printed in full.
- The local web interface (`security-hub ui`) can be driven by another website, another user of the machine, or by
  scanned code.
- The HTML report, the pull-request comment or a "Fix with AI" prompt lets text from the scanned project act as
  markup, as a command, or as an instruction to an assistant.
- A vulnerability in the published npm packages or in their dependencies that affects users.

## What is not

- A wrong finding or a missed vulnerability in the scanned code (open a normal issue: false positives and false
  negatives are expected, see `docs/validation.md`).
- Anything in `examples/` and `labs/`: they are vulnerable on purpose (the lab binds to `127.0.0.1` only).
- Vulnerabilities in development-only dependencies that are not part of the published packages (they are still tracked
  and updated by Dependabot).

## How the project protects its users

- The scanner is offline. The only network call is `scan --audit`, which runs `npm audit` and only when asked.
- A scan parses code but never runs it; `fix` shows a diff and changes nothing without `--write`, refuses files with
  uncommitted changes, never writes through a symbolic link and never prints a secret.
- One hostile file costs one note: parsing, analysis and each check have time and failure limits.
- `security-hub ui` listens on `127.0.0.1` only, checks the `Host` header, needs a per-run token that is not in the page,
  and serves a strict Content-Security-Policy.
- git is run with `core.fsmonitor` and friends switched off, so a folder with a hostile `.git/config` cannot run commands.
- Releases are published from GitHub Actions with npm Trusted Publishing (OIDC): there is no long-lived npm token.
