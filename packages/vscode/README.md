# Security Testing Hub for VS Code

Shows the findings of [Security Testing Hub](https://github.com/dam1r-dev/security-testing-hub) in the Problems panel, a score in the
status bar, and a quick fix on every finding: **copy the fix prompt for my AI assistant** (paste it into Cursor, Claude, Copilot or
ChatGPT).

> **Status: early.** The code is built and its logic is tested (`npm test` in this repository), but it has not been run inside an
> editor by its author. Try it as described below and report what you see. It is not published to the Marketplace yet.

## Try it

```bash
git clone https://github.com/dam1r-dev/security-testing-hub
cd security-testing-hub && npm ci && npm run build
code packages/vscode            # then press F5: a second VS Code window opens with the extension loaded
```

In that window open a project, run **Security Hub: Scan the workspace** from the command palette (or click the shield in the status
bar). To make an installable file: `cd packages/vscode && npx @vscode/vsce package` and *Extensions -> ... -> Install from VSIX*.

## What it does

- runs `npx --yes security-hub@latest scan . --format json --prompts` in the workspace folder (Node.js 18+ must be installed; the
  scanner uses a native parser, so it runs as a program and not inside the editor);
- shows critical / high as errors, medium as warnings, low as information, with the rule id as the problem code;
- `securityHub.minSeverity` limits what is shown, `securityHub.scanOnSave` scans again on every save (the whole project, so a call into
  another file is still followed).

Nothing is uploaded: the scan runs on your computer. The project's `.security-hub.json` and baseline are honoured like on the
command line.

## Safety choices

- **Off in an untrusted workspace** (`capabilities.untrustedWorkspaces.supported: false`): `npx security-hub` run inside a folder
  prefers a copy installed in that folder, so a project you do not trust could provide its own.
- **`securityHub.command` is machine-scoped:** a workspace's `.vscode/settings.json` cannot change what the extension runs.
  Use `security-hub` if you installed it globally, or pin a version (`npx --yes security-hub@0.6.0`).
