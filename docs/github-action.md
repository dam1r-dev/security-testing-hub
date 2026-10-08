# GitHub Action

Scan every pull request automatically. The action reports what the **change** touches — as inline
annotations in the diff, one summary comment with the 0–100 score, and the job summary — and can fail
the check when something serious is found.

## Quick start

`.github/workflows/security.yml` in your repository:

```yaml
name: Security scan
on:
  pull_request:

permissions:
  contents: read
  pull-requests: write   # lets the action post / update its summary comment

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0   # needed to find which files the pull request changed

      - uses: dam1r-dev/security-testing-hub@v0
        with:
          fail-on: high    # fail the check on any high / critical finding (optional)
```

That is all. Open a pull request and the check runs.

## What you get

| Where | What |
|---|---|
| **Files changed** tab | An inline `error` / `warning` / `notice` on the exact line (critical + high = error, medium = warning, low = notice) |
| **Pull request conversation** | One comment — updated on every push, never a new one — with the score, counts and a table linking to each line |
| **Job summary** | The same report on the run page |
| **"Fix with AI" block** | A collapsed block in the comment with one prompt for the listed findings, ready to paste into Cursor / Claude / Copilot |
| **Code scanning** (optional) | `sarif: true` also uploads the results to the Security tab |
| **Check status** | Red when a reported finding is at or above `fail-on`; otherwise green |

## Only your change, but the whole project is analysed

On pull requests the action lists **only findings in files the pull request changed** — an old finding in
code you didn't touch never blocks an unrelated PR. The scan itself still covers the whole project, so a
changed route handler that passes user input into an *unchanged* query helper is still found (that is what
the cross-file analysis is for). The comment says how many findings in untouched files were left out.
Set `changed-only: "false"` to report everything.

On a push (or any non-PR event) the full report is produced.

## Inputs

| Input | Default | |
|---|---|---|
| `path` | `.` | Folder to scan, relative to the repository root. |
| `fail-on` | *(never)* | `low` \| `medium` \| `high` \| `critical`. Fail the job if a reported finding is at or above it. |
| `severity` | *(all)* | Only report findings at or above this level. |
| `changed-only` | `true` | On pull requests, report only changed files (see above). |
| `comment` | `true` | Post / update the pull request comment. Needs `pull-requests: write`. |
| `sarif` | `false` | Upload to code scanning. Needs `security-events: write`; private repositories need GitHub Code Security. |
| `ignore` | | Extra path patterns to skip, one per line (same syntax as `.security-hub-ignore`). |
| `include-tests` | `false` | Also scan test folders and `*.test.*` / `*.spec.*` files. |
| `version` | `latest` | `security-hub-scanner` version: `latest`, an exact one like `0.4.0` (recommended for reproducible CI), or `local` (use the checked-out, already built `packages/scanner` — this repository's own workflow does that). |
| `github-token` | `${{ github.token }}` | Used for the comment only. |

Outputs: `score` (0–100) and `findings` (count), e.g. to show them in a badge or gate a later step.

## Handling a finding that is wrong

Put `// security-hub-ignore` on the flagged line or the line above (optionally with a rule id and a reason:
`// security-hub-ignore sql-injection -- reviewed, input is signed`), or list paths in a
`.security-hub-ignore` file. The comment always says how many findings were hidden this way.
See the [README](../README.md#silencing-a-finding-that-is-wrong-or-accepted).

## Pull requests from forks

GitHub gives workflows triggered by a fork's pull request a **read-only** token. The action detects that,
skips the comment with a warning, and still produces the annotations, the job summary and the pass/fail
result — the check itself works. Don't switch to `pull_request_target` to get comments on fork PRs: that
event runs with write access and secrets, and checking out the fork's code under it is a well-known way to
leak them. The action never executes the code it scans, but the risk of that trigger is in the checkout.

## Security notes

- Inputs are passed to the script through environment variables, never interpolated into shell text.
- Text from scanned code (file names, snippets) is escaped before it goes into a comment or a workflow
  command, so a malicious pull request can't inject markup, `@`-mentions or extra workflow commands.
- The action edits only **its own** comment (found by a hidden marker *and* a bot author).
- Nothing leaves the runner except the comment/SARIF you enabled; the scanner is installed from npm
  (`security-hub-scanner`) and runs locally.

## Troubleshooting

- *"Could not diff against origin/main"* — the checkout is shallow. Use `fetch-depth: 0` (the action also
  tries to fetch the base branch itself).
- *No comment appears* — add `pull-requests: write` under `permissions`, or the PR comes from a fork.
- *Everything is reported, not just my change* — the event isn't a pull request, or `changed-only` is off.
