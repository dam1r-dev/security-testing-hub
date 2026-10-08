import * as path from "path";
import { Finding, ScanSummary, VulnerabilityType } from "../types";

/**
 * "Fix with AI": a ready-to-paste prompt for Cursor / Claude / Copilot for each finding.
 * The audience writes code with an assistant, so the shortest path from "the scanner found a
 * problem" to "it is fixed" is handing the assistant everything it needs: where, what, how.
 *
 * Findings are already redacted (a secret never appears in a message or snippet), and this
 * module only ever builds text from those fields — so a prompt can never contain a secret.
 */

const HOW_TO_FIX: Record<VulnerabilityType, string> = {
  "sql-injection":
    "Use parameterized queries: put placeholders (?, $1, :name) in the SQL text and pass the values separately " +
    "(e.g. db.query('... WHERE id = ?', [id])). Never build SQL with + or template strings. If this is a table or " +
    "column name, pick it from a fixed allowlist instead.",
  xss:
    "Never put request data into an HTML string. Return JSON (res.json) for data, or render through a template engine " +
    "with auto-escaping; if raw HTML is unavoidable, escape the value (e.g. the escape-html package) first.",
  "command-injection":
    "Do not build a shell command from input. Use child_process.execFile / spawn with an argument array (no shell), " +
    "and validate the value against an allowlist or a strict pattern first.",
  "path-traversal":
    "Resolve the final path with path.resolve against a fixed base directory and reject it unless it still starts " +
    "with that base (base + path.sep). Better: map an id to a known file instead of using a user-supplied name.",
  ssrf:
    "Only fetch URLs whose host and scheme are on an allowlist; reject loopback, link-local (169.254.x.x) and private " +
    "IP ranges after DNS resolution, and do not follow redirects blindly.",
  csrf:
    "Protect state-changing routes: set the session cookie with SameSite=Lax (or Strict), verify the Origin/Referer " +
    "header, and/or require an anti-forgery token (double-submit cookie or a CSRF middleware).",
  idor:
    "Before returning or changing the record, check that it belongs to the logged-in user (compare its owner id with " +
    "the session user id) and return 404/403 otherwise. Never trust the id from the URL alone.",
  "broken-access-control":
    "Add authentication and an authorization check (role/permission) to this route, ideally through shared middleware " +
    "so that every admin route gets it by default.",
  "insecure-role-assignment":
    "Never read a role or admin flag from the request body, cookie or header. Decide roles on the server from the " +
    "authenticated user's record.",
  "insecure-file-upload":
    "Validate the file extension against an allowlist AND the real content (magic bytes), ignore the client's " +
    "Content-Type, generate a new file name, limit the size, and store uploads outside the web root.",
  "username-enumeration":
    "Return the same message and the same status code for 'unknown user' and 'wrong password' (e.g. 'Invalid " +
    "username or password'), and keep response time similar.",
  "code-injection":
    "Never eval / new Function / vm-run input. Parse data with JSON.parse or a schema validator; if you need to " +
    "evaluate expressions, use a library that supports a strict allowlist of operations.",
  "open-redirect":
    "Redirect only to relative paths you build yourself, or check the target host against an allowlist before " +
    "redirecting. Reject values starting with // or containing a scheme.",
  "nosql-injection":
    "Convert request values to the expected primitive type (String(x), Number(x)) or validate with a schema (zod, joi) " +
    "before they reach the query; never pass raw req.body objects as filters, and avoid $where.",
  "insecure-deserialization":
    "Never deserialize untrusted data with a format that can run code (node-serialize, unserialize). Use JSON.parse " +
    "and validate the shape of the result.",
  xxe:
    "Parse untrusted XML with external entities and DTD processing turned off (remove noent: true), or use a parser " +
    "that disables them by default.",
  "hardcoded-secret":
    "Do NOT write the real value anywhere in your answer or the code. Replace the literal with process.env.<NAME> " +
    "(server-side only; never behind a NEXT_PUBLIC_/VITE_/REACT_APP_ prefix), put the value in a gitignored .env file " +
    "and add a .env.example with empty values. If a .env file is tracked, run `git rm --cached .env` and add it to " +
    ".gitignore. Remind me that the old key must be revoked and replaced, because it stays in the git history.",
  "supabase-rls":
    "Enable Row Level Security on every table in the exposed schema (ALTER TABLE ... ENABLE ROW LEVEL SECURITY) and write " +
    "policies that scope each row to its owner, e.g. USING ((select auth.uid()) = user_id) and WITH CHECK ((select auth.uid()) = " +
    "user_id). Never use USING (true) for writes; use app_metadata, not user_metadata, for roles; create views WITH " +
    "(security_invoker = true); pin search_path on SECURITY DEFINER functions. Put the change in a new migration file.",
  "supabase-auth":
    "On the server, call supabase.auth.getUser() (it re-validates the token with Supabase) instead of getSession(), and use the " +
    "returned user. Decide roles and permissions from app_metadata or a roles table that only the server can write, never from " +
    "user_metadata, which users can edit.",
  "firebase-rules":
    "Rewrite the rules so each document or file is tied to its owner: allow read, write: if request.auth != null && " +
    "request.auth.uid == resource.data.ownerId (or the {userId} segment of the path). Never use `if true`, a test-mode date, or a " +
    "bare `request.auth != null` for writes. For the Realtime Database use \"auth != null && auth.uid === $uid\". Deploy with " +
    "`firebase deploy --only firestore:rules` (or storage / database) and test with the Rules Playground or the emulator.",
};

const REQUIREMENTS = [
  "Change only what is needed to fix the issue; keep the behavior the same for valid input.",
  "Show the exact changes (a diff or the full corrected function).",
  "Explain in one sentence what was wrong.",
  "Avoid adding new dependencies unless there is no reasonable alternative.",
  "If you cannot fix it safely without more context, tell me exactly what you need to see.",
];

export interface FixPromptOptions {
  /** Show file paths relative to this folder. */
  relativeTo?: string;
}

function displayFile(finding: Finding, options: FixPromptOptions): string {
  const file = options.relativeTo ? path.relative(options.relativeTo, finding.location.file) : finding.location.file;
  return file.split(path.sep).join("/");
}

function oneLine(text: string, max: number): string {
  const flat = text.replace(/\s+/g, " ").trim();
  return flat.length > max ? `${flat.slice(0, max - 3)}...` : flat;
}

function issueBlock(finding: Finding, options: FixPromptOptions): string[] {
  return [
    `Rule: ${finding.ruleId} (${finding.severity})`,
    `Where: ${displayFile(finding, options)}, line ${finding.location.startLine}`,
    `Problem: ${oneLine(finding.message, 700)}`,
    `Code: ${oneLine(finding.sinkSnippet, 200)}`,
    `How to fix: ${HOW_TO_FIX[finding.ruleId]}`,
  ];
}

/** A prompt for one finding. */
export function fixPromptFor(finding: Finding, options: FixPromptOptions = {}): string {
  return [
    "Fix a security issue in my project (found by the static analyzer Security Testing Hub).",
    "",
    ...issueBlock(finding, options),
    "",
    "Requirements:",
    ...REQUIREMENTS.map((r) => `- ${r}`),
  ].join("\n");
}

const SEVERITY_ORDER = ["critical", "high", "medium", "low"];

/** One prompt covering every finding in the summary (most severe first), for pasting into an assistant in one go. */
export function toFixPrompt(summary: ScanSummary, options: FixPromptOptions & { maxFindings?: number } = {}): string {
  const all = summary.results
    .flatMap((r) => r.findings)
    .sort((a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity));
  if (all.length === 0) return "";
  const limit = options.maxFindings ?? 15;
  const lines = [
    `Fix these ${Math.min(all.length, limit)} security issue(s) in my project (found by the static analyzer Security Testing Hub). ` +
      "Handle them one at a time, most severe first.",
    "",
  ];
  all.slice(0, limit).forEach((finding, i) => {
    lines.push(`## Issue ${i + 1}`, ...issueBlock(finding, options), "");
  });
  if (all.length > limit) lines.push(`(${all.length - limit} more issue(s) not included; run the scan again after these are fixed.)`, "");
  lines.push("Requirements for every fix:", ...REQUIREMENTS.map((r) => `- ${r}`));
  return lines.join("\n");
}

/** A markdown code fence that no backtick run inside `content` can close early. */
export function fenced(content: string): string {
  const longest = Math.max(0, ...[...content.matchAll(/`+/g)].map((m) => m[0].length));
  const fence = "`".repeat(Math.max(3, longest + 1));
  return `${fence}text\n${content}\n${fence}`;
}
