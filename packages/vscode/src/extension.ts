import { execFile } from "child_process";
import * as vscode from "vscode";
import { Item, Severity, isSeverity, parseReport, splitCommand, statusText, statusTooltip, toItems } from "./report";

// The editor side: runs the scanner as a program (not inside the editor: the scanner uses a native parser built for plain Node,
// which the editor's own runtime cannot load), shows what it found in the Problems panel and the status bar, and offers the
// "copy the fix prompt for my AI assistant" quick fix. Nothing is sent anywhere by this extension.

const SOURCE = "Security Hub";
const SOURCE_FILE = /\.(?:[cm]?[jt]sx?|sql|rules|env[\w.]*)$/i;

let collection: vscode.DiagnosticCollection;
let status: vscode.StatusBarItem;
let running = false;
const prompts = new Map<string, string>(); // diagnostic key -> prompt

function key(uri: vscode.Uri, range: vscode.Range, rule: string): string {
  return `${uri.toString()}#${range.start.line}:${range.start.character}:${rule}`;
}

function severityOf(level: Item["level"]): vscode.DiagnosticSeverity {
  return level === "error" ? vscode.DiagnosticSeverity.Error : level === "warning" ? vscode.DiagnosticSeverity.Warning : vscode.DiagnosticSeverity.Information;
}

function run(command: string, args: string[], cwd: string): Promise<string> {
  const [program, ...head] = splitCommand(command);
  if (!program) return Promise.reject(new Error("securityHub.command is empty"));
  return new Promise((resolve, reject) => {
    // `shell` on Windows only: npx is npx.cmd there. The command comes from a machine-scoped setting, and every argument after it is ours.
    execFile(program, [...head, ...args], { cwd, maxBuffer: 256 * 1024 * 1024, shell: process.platform === "win32", env: { ...process.env, CI: "1" } }, (error, stdout, stderr) => {
      // exit code 1 is "findings at or above --fail-on": not used here, but a non-zero exit with a report is still a report
      if (stdout.includes('"results"')) resolve(stdout);
      else reject(new Error((stderr || (error && error.message) || "the scanner did not run").trim().split("\n").slice(-4).join(" ").slice(0, 400)));
    });
  });
}

async function scan(): Promise<void> {
  const folder = vscode.workspace.workspaceFolders?.[0];
  if (!folder) {
    void vscode.window.showInformationMessage("Open a folder first: Security Hub scans the project you have open.");
    return;
  }
  if (running) return;
  running = true;
  status.text = "$(sync~spin) Security Hub";
  try {
    const settings = vscode.workspace.getConfiguration("securityHub");
    const configured = settings.get<string>("minSeverity", "low");
    const minimum: Severity = isSeverity(configured) ? configured : "low";
    const stdout = await vscode.window.withProgress({ location: vscode.ProgressLocation.Window, title: "Security Hub: scanning" }, () =>
      run(settings.get<string>("command", "npx --yes security-hub@latest"), ["scan", ".", "--format", "json", "--prompts"], folder.uri.fsPath),
    );
    const report = parseReport(stdout);
    const items = toItems(report, folder.uri.fsPath, minimum);
    collection.clear();
    prompts.clear();
    const byFile = new Map<string, vscode.Diagnostic[]>();
    for (const item of items) {
      const uri = vscode.Uri.file(item.file);
      const range = new vscode.Range(item.line, item.column, item.endLine, Math.max(item.endColumn, item.column + 1));
      const diagnostic = new vscode.Diagnostic(range, item.message, severityOf(item.level));
      diagnostic.source = SOURCE;
      diagnostic.code = item.rule;
      byFile.set(uri.toString(), [...(byFile.get(uri.toString()) ?? []), diagnostic]);
      if (item.prompt) prompts.set(key(uri, range, item.rule), item.prompt);
    }
    for (const [uri, list] of byFile) collection.set(vscode.Uri.parse(uri), list);
    status.text = statusText(report, items.length);
    status.tooltip = statusTooltip(report, items.length);
  } catch (error) {
    status.text = "$(shield) Security Hub: error";
    status.tooltip = String((error as Error).message);
    void vscode.window.showErrorMessage(`Security Hub: ${(error as Error).message}`);
  } finally {
    running = false;
  }
}

class FixPromptActions implements vscode.CodeActionProvider {
  provideCodeActions(document: vscode.TextDocument, range: vscode.Range, context: vscode.CodeActionContext): vscode.CodeAction[] {
    const actions: vscode.CodeAction[] = [];
    for (const diagnostic of context.diagnostics) {
      if (diagnostic.source !== SOURCE) continue;
      const prompt = prompts.get(key(document.uri, diagnostic.range, String(diagnostic.code)));
      if (!prompt) continue;
      const action = new vscode.CodeAction("Security Hub: copy the fix prompt for my AI assistant", vscode.CodeActionKind.QuickFix);
      action.diagnostics = [diagnostic];
      action.command = { command: "securityHub.copyFixPrompt", title: "Copy the fix prompt", arguments: [prompt] };
      actions.push(action);
    }
    void range;
    return actions;
  }
}

export function activate(context: vscode.ExtensionContext): void {
  collection = vscode.languages.createDiagnosticCollection("securityHub");
  status = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 0);
  status.command = "securityHub.scan";
  status.text = "$(shield) Security Hub";
  status.tooltip = "Click to scan this project";
  status.show();

  context.subscriptions.push(
    collection,
    status,
    vscode.commands.registerCommand("securityHub.scan", scan),
    vscode.commands.registerCommand("securityHub.clear", () => {
      collection.clear();
      prompts.clear();
      status.text = "$(shield) Security Hub";
    }),
    vscode.commands.registerCommand("securityHub.copyFixPrompt", async (prompt?: string) => {
      // from the quick fix the prompt is passed in; from the command palette, use the finding under the cursor
      let text = prompt;
      if (!text) {
        const editor = vscode.window.activeTextEditor;
        const here = editor?.selection.active;
        const diagnostic = editor && here ? collection.get(editor.document.uri)?.find((d) => d.range.contains(here)) : undefined;
        text = diagnostic && editor ? prompts.get(key(editor.document.uri, diagnostic.range, String(diagnostic.code))) : undefined;
      }
      if (!text) {
        void vscode.window.showInformationMessage("Put the cursor on a Security Hub finding first.");
        return;
      }
      await vscode.env.clipboard.writeText(text);
      void vscode.window.showInformationMessage("Fix prompt copied: paste it into Cursor, Claude, Copilot or ChatGPT.");
    }),
    vscode.languages.registerCodeActionsProvider({ scheme: "file" }, new FixPromptActions(), { providedCodeActionKinds: [vscode.CodeActionKind.QuickFix] }),
    vscode.workspace.onDidSaveTextDocument((document) => {
      if (vscode.workspace.getConfiguration("securityHub").get<boolean>("scanOnSave", false) && SOURCE_FILE.test(document.fileName)) void scan();
    }),
  );
}

export function deactivate(): void {
  collection?.dispose();
}
