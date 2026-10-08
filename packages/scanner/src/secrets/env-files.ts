import { execFileSync } from "child_process";
import * as fs from "fs";
import * as path from "path";
import { applyInlineSuppressions, compileIgnorePatterns, parseIgnoreFile } from "../suppress";
import { Finding, ScanResult } from "../types";
import { findKnownSecrets, isSensitiveName, looksLikeSecret, normalizeName, redact } from "./detect";

/**
 * `.env` files hold real credentials by design — that is fine as long as they never reach
 * the repository. This finds the ones that are (or are about to be) committed.
 *
 * `.env.example` / `.env.sample` / `.env.template` are meant to be committed and are skipped.
 */

const ENV_FILE = /^\.env(\.[\w.-]+)?$/;
const TEMPLATE_ENV_FILE = /\.(example|sample|template|dist|defaults?|schema)$/i;
const MAX_FINDINGS_PER_FILE = 10;

type GitState = "tracked" | "not-ignored" | "ignored" | "unknown";

function git(cwd: string, args: string[]): { ok: boolean; stderr: string } {
  try {
    execFileSync("git", args, { cwd, stdio: ["ignore", "pipe", "pipe"] });
    return { ok: true, stderr: "" };
  } catch (err) {
    const stderr = (err as { stderr?: Buffer }).stderr?.toString() ?? "";
    return { ok: false, stderr };
  }
}

/** Is this file committed, safely ignored, or sitting there one `git add .` away from being committed? */
function gitState(file: string, root: string): GitState {
  const dir = path.dirname(file);
  const name = path.basename(file);
  const inside = git(dir, ["rev-parse", "--is-inside-work-tree"]);
  if (inside.ok) {
    if (git(dir, ["ls-files", "--error-unmatch", "--", name]).ok) return "tracked";
    return git(dir, ["check-ignore", "-q", "--", name]).ok ? "ignored" : "not-ignored";
  }
  // No git (or not a repository): fall back to reading .gitignore.
  try {
    const patterns = parseIgnoreFile(fs.readFileSync(path.join(root, ".gitignore"), "utf8")).filter((p) => !p.startsWith("!"));
    const relative = path.relative(root, file).split(path.sep).join("/");
    return compileIgnorePatterns(patterns)(relative) ? "ignored" : "unknown";
  } catch {
    return "unknown";
  }
}

function envFilesUnder(root: string, skipDirs: Set<string>, isIgnored: (relative: string) => boolean): string[] {
  const files: string[] = [];
  const stack = [root];
  while (stack.length > 0) {
    const current = stack.pop() as string;
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(current, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const entry of entries) {
      const full = path.join(current, entry.name);
      if (isIgnored(path.relative(root, full).split(path.sep).join("/"))) continue;
      if (entry.isDirectory()) {
        if (!skipDirs.has(entry.name) && entry.name !== ".git") stack.push(full);
      } else if (entry.isFile() && ENV_FILE.test(entry.name) && !TEMPLATE_ENV_FILE.test(entry.name)) {
        files.push(full);
      }
    }
  }
  return files;
}

/** `KEY=value`, `export KEY="value"  # note` -> { key, value } */
function parseLine(line: string): { key: string; value: string } | undefined {
  const match = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_.-]*)\s*=\s*(.*)$/.exec(line);
  if (!match) return undefined;
  let value = (match[2] ?? "").trim();
  const quote = value[0];
  if ((quote === '"' || quote === "'") && value.lastIndexOf(quote) > 0) {
    value = value.slice(1, value.lastIndexOf(quote));
  } else {
    value = value.replace(/\s+#.*$/, "");
  }
  return { key: match[1] as string, value };
}

export function scanEnvFiles(
  root: string,
  skipDirs: Set<string>,
  isIgnored: (relative: string) => boolean,
): ScanResult[] {
  const results: ScanResult[] = [];
  for (const file of envFilesUnder(root, skipDirs, isIgnored)) {
    let text: string;
    try {
      text = fs.readFileSync(file, "utf8");
    } catch {
      continue;
    }
    const lines = text.split(/\r?\n/);
    const secretLines: Array<{ line: number; key: string; value: string }> = [];
    lines.forEach((raw, i) => {
      if (raw.trim().startsWith("#")) return;
      const entry = parseLine(raw);
      if (!entry || entry.value === "") return;
      const isKnown = findKnownSecrets(entry.value).length > 0;
      if (isKnown || (isSensitiveName(normalizeName(entry.key)) && looksLikeSecret(entry.value))) {
        secretLines.push({ line: i + 1, key: entry.key, value: entry.value });
      }
    });
    if (secretLines.length === 0) continue;

    const state = gitState(file, root);
    if (state === "ignored") continue; // exactly how a .env file should be handled

    const tracked = state === "tracked";
    const display = path.basename(file);
    const findings: Finding[] = secretLines.slice(0, MAX_FINDINGS_PER_FILE).map(({ line, key, value }) => ({
      ruleId: "hardcoded-secret",
      severity: tracked ? "critical" : "high",
      confidence: tracked ? "high" : "medium",
      message: tracked
        ? `${display} is committed to git and holds a real-looking value for ${key} (${redact(value)}). Everyone with ` +
          `access to the repository — and anyone who ever cloned it — has this secret. Revoke / rotate it now, run ` +
          `\`git rm --cached ${display}\`, add it to .gitignore and commit a ${display}.example with empty values instead. ` +
          `Deleting the file is not enough: the value stays in the git history.`
        : `${display} holds a real-looking value for ${key} (${redact(value)}) and is not ignored by git${state === "unknown" ? " (no git repository was found to confirm)" : ""}: ` +
          `one \`git add .\` away from being committed. Add \`${display}\` to .gitignore now, and commit a ${display}.example ` +
          `with empty values instead.`,
      location: { file, startLine: line, startColumn: 1, endLine: line, endColumn: (lines[line - 1] ?? "").length + 1 },
      sourceSnippet: redact(value),
      sinkSnippet: `${key}=<redacted>`,
    }));

    const { kept, suppressed } = applyInlineSuppressions(findings, text);
    const result: ScanResult = { file, findings: kept };
    if (suppressed > 0) result.suppressed = suppressed;
    results.push(result);
  }
  return results;
}
