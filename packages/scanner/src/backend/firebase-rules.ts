import { Finding, Severity } from "../types";

/**
 * Firebase security rules are the only thing between the internet and your database: the Firebase
 * config (apiKey, projectId, ...) is public by design and ships in every browser bundle, so anyone can talk
 * to Firestore, Storage and the Realtime Database directly. `allow read, write: if true;` (or the console's
 * "test mode" default, `if request.time < timestamp.date(...)`) therefore means "the whole database belongs
 * to whoever finds the project id".
 */

const SENSITIVE_PATH = /user|profile|customer|order|payment|invoice|message|chat|account|subscription|private|secret|token|member|patient|kyc|billing|admin|session/i;
// Personal / financial data: a public read is a leak. Messages and chats are "sensitive" too, but whether a chat is
// public is a design choice (a public chat room, a guestbook), so those get a lower severity.
const PII_PATH = /user|profile|customer|order|payment|invoice|account|subscription|private|secret|token|member|patient|kyc|billing|admin|session/i;

type Method = "get" | "list" | "create" | "update" | "delete";

/** Index of the `}` that closes the block opened just before `from`. */
function blockEnd(text: string, from: number): number {
  let depth = 1;
  for (let i = from; i < text.length; i++) {
    if (text[i] === "{") depth++;
    else if (text[i] === "}" && --depth === 0) return i;
  }
  return text.length;
}

/** `function name(params) { ... }` -> body text (everything between the braces). */
function collectFunctions(text: string): Map<string, { params: string; body: string }> {
  const functions = new Map<string, { params: string; body: string }>();
  for (const m of text.matchAll(/\bfunction\s+(\w+)\s*\(([^)]*)\)\s*\{/g)) {
    const start = (m.index ?? 0) + m[0].length;
    functions.set(m[1] as string, { params: (m[2] as string).trim(), body: text.slice(start, blockEnd(text, start)) });
  }
  return functions;
}

/** Zero-argument helpers such as `function ok() { return request.auth != null; }` are replaced by their expression. */
function inlineSimpleFunctions(condition: string, functions: Map<string, { params: string; body: string }>): string {
  let out = condition;
  for (let pass = 0; pass < 4; pass++) {
    const next = out.replace(/\b(\w+)\s*\(\s*\)/g, (whole, name: string) => {
      const fn = functions.get(name);
      const only = fn && fn.params === "" ? /^\s*return\s+([^;]*);\s*$/.exec(fn.body)?.[1] : undefined;
      return only === undefined ? whole : `(${only})`;
    });
    if (next === out) break;
    out = next;
  }
  return out;
}

/** The condition plus the body of every helper it calls (recursively), for "does this ever look at request.auth?". */
function withCalledFunctions(condition: string, functions: Map<string, { params: string; body: string }>): string {
  const seen = new Set<string>();
  let text = condition;
  for (let pass = 0; pass < 5; pass++) {
    let added = false;
    for (const [name, fn] of functions) {
      if (!seen.has(name) && new RegExp(`\\b${name}\\s*\\(`).test(text)) {
        seen.add(name);
        text += `\n${fn.body}`;
        added = true;
      }
    }
    if (!added) break;
  }
  return text;
}

function expandMethods(text: string): Set<Method> {
  const methods = new Set<Method>();
  for (const raw of text.split(",")) {
    const m = raw.trim().toLowerCase();
    if (m === "read") (["get", "list"] as const).forEach((x) => methods.add(x));
    else if (m === "write") (["create", "update", "delete"] as const).forEach((x) => methods.add(x));
    else if (["get", "list", "create", "update", "delete"].includes(m)) methods.add(m as Method);
  }
  return methods;
}

/** Blanks out comments but keeps every newline, so line numbers stay right. */
function stripComments(text: string): string {
  return text.replace(/\/\*[\s\S]*?\*\//g, (c) => c.replace(/[^\n]/g, " ")).replace(/\/\/[^\n]*/g, (c) => " ".repeat(c.length));
}

function lineAt(text: string, index: number): number {
  let line = 1;
  for (let i = 0; i < index; i++) if (text.charCodeAt(i) === 10) line++;
  return line;
}

function unwrap(condition: string): string {
  let c = condition.replace(/\s+/g, "");
  while (c.startsWith("(") && c.endsWith(")") && balancedOuter(c)) c = c.slice(1, -1);
  return c;
}

function balancedOuter(c: string): boolean {
  let depth = 0;
  for (let i = 0; i < c.length; i++) {
    if (c[i] === "(") depth++;
    if (c[i] === ")") depth--;
    if (depth === 0 && i < c.length - 1) return false;
  }
  return true;
}

/** `request.auth != null` and friends: a signed-in user of any kind, with no tie to the data they touch. */
function isSignedInOnly(c: string): boolean {
  const rest = c
    .replace(/request\.auth!=null/g, "")
    .replace(/request\.auth\.uid!=null/g, "")
    .replace(/request\.auth\.token\.email_verified==true/g, "")
    .replace(/request\.auth\.token\.firebase\.sign_in_provider!='anonymous'/g, "")
    .replace(/[&()]/g, "");
  return (c.includes("request.auth!=null") || c.includes("request.auth.uid!=null")) && rest === "";
}

function testModeDate(c: string): Date | undefined {
  const m = /^request\.time<timestamp\.date\((\d{4}),(\d{1,2}),(\d{1,2})\)$/.exec(c);
  return m ? new Date(Date.UTC(Number(m[1]), Number(m[2]) - 1, Number(m[3]))) : undefined;
}

function makeFinding(file: string, line: number, severity: Severity, confidence: Finding["confidence"], message: string, source: string, snippet: string): Finding {
  return {
    ruleId: "firebase-rules",
    severity,
    confidence,
    message,
    location: { file, startLine: line, startColumn: 1, endLine: line, endColumn: snippet.length + 1 },
    sourceSnippet: source,
    sinkSnippet: snippet.length > 160 ? `${snippet.slice(0, 157)}...` : snippet,
  };
}

export type RulesKind = "firestore" | "storage";

/** Checks a `firestore.rules` / `storage.rules` file. */
export function analyzeFirebaseRules(source: string, file: string, kind: RulesKind, now: Date = new Date()): Finding[] {
  const text = stripComments(source);
  const findings: Finding[] = [];
  const frames: string[] = [];
  const blocks: string[] = []; // text of each open `match` block (so the fields it mentions are known), "" otherwise
  const functions = collectFunctions(text);
  const store = kind === "storage" ? "Cloud Storage" : "Firestore";
  const noun = kind === "storage" ? "file" : "document";
  const token = /\bmatch\s+((?:[^\s{};]|\{[^{}]*\})+)\s*\{|\bfunction\s+\w+\s*\([^)]*\)\s*\{|\ballow\s+([\w\s,]+?)\s*(?::\s*if\s+([^;]*))?;|\{|\}/g;

  for (let m = token.exec(text); m !== null; m = token.exec(text)) {
    if (m[0] === "}") {
      frames.pop();
      blocks.pop();
      continue;
    }
    if (m[0].startsWith("match")) {
      frames.push((m[1] as string).trim());
      const start = m.index + m[0].length;
      blocks.push(text.slice(start, blockEnd(text, start)));
      continue;
    }
    if (m[0].startsWith("function") || m[0] === "{") {
      frames.push("");
      blocks.push("");
      continue;
    }

    // allow <methods> [: if <condition>];
    const methods = expandMethods(m[2] as string);
    const writes = (["create", "update", "delete"] as const).filter((x) => methods.has(x));
    const modifies = (["update", "delete"] as const).filter((x) => methods.has(x));
    const reads = methods.has("get") || methods.has("list");
    const rawCondition = m[3] === undefined ? "true" : m[3];
    const condition = unwrap(inlineSimpleFunctions(rawCondition, functions));
    const blockText = [...blocks].reverse().find((b) => b !== "") ?? "";
    // the whole picture of this rule: its condition, the helpers it calls, and the block's own field validators
    const rulePicture = withCalledFunctions(`${rawCondition}\n${blockText}`, functions);
    // Field names that hold personal or financial data: a public read of a document that has them is a leak even when
    // the collection's own name ("reports", "volunteers") says nothing.
    const piiFields = [...new Set([...rulePicture.matchAll(/['".]\s*(\w*(?:phone|cedula|dni|ssn|passport|e-?mail|address|birth|iban|bank|password|secret|salary)\w*)/gi)].map((x) => x[1] as string))].slice(0, 4);
    const line = lineAt(text, m.index);
    const snippet = m[0].replace(/\s+/g, " ").trim();

    const fullPath = frames.join("");
    const relative = fullPath.replace(/^\/databases\/\{[^}]+\}\/documents/, "").replace(/^\/b\/\{[^}]+\}\/o/, "");
    const isGlobal = relative === "" || /^\/\{\w+=\*\*\}$/.test(relative);
    const collection = /^\/([A-Za-z0-9_-]+)/.exec(relative)?.[1] ?? "";
    const where = isGlobal ? `EVERY ${noun} in ${store}` : `${noun}s under ${relative || "/"}`;
    const sensitive = SENSITIVE_PATH.test(collection);

    if (condition === "true") {
      if (writes.length > 0) {
        findings.push(
          makeFinding(
            file,
            line,
            "critical",
            "high",
            `This rule lets ANYONE on the internet ${[reads ? "read" : "", writes.length === 3 ? "write" : writes.join("/")].filter(Boolean).join(" and ")} ${where} (\`if true\`). ` +
              `Your Firebase config is public by design, so nothing else protects the data. Require a signed-in user and tie each ${noun} to its owner: ` +
              `allow write: if request.auth != null && request.auth.uid == resource.data.ownerId;`,
            "allow ... if true",
            snippet,
          ),
        );
      } else if (reads && (isGlobal || sensitive || piiFields.length > 0)) {
        const personal = piiFields.length > 0 && !isGlobal ? `, which holds personal data (${piiFields.join(", ")})` : sensitive && !isGlobal ? ", which looks like private data" : "";
        findings.push(
          makeFinding(
            file,
            line,
            // Public reads of ALL files in Storage are common (public images); of all Firestore documents they are not.
            isGlobal ? (kind === "storage" ? "medium" : "critical") : PII_PATH.test(collection) || piiFields.length > 0 ? "high" : "medium",
            "high",
            `This rule lets ANYONE on the internet read ${where}${personal} (\`if true\`). ` +
              `Restrict reads to the signed-in owner: allow read: if request.auth != null && request.auth.uid == resource.data.ownerId;`,
            "allow read if true",
            snippet,
          ),
        );
      }
      continue;
    }

    const expires = testModeDate(condition);
    if (expires) {
      const active = expires.getTime() > now.getTime();
      findings.push(
        makeFinding(
          file,
          line,
          active ? "critical" : "medium",
          "high",
          active
            ? `This is Firebase's "test mode" rule: until ${expires.toISOString().slice(0, 10)} ANYONE can read and write ${where}. ` +
                `It was meant for the first day of development; replace it with rules that require a signed-in owner before you share the app.`
            : `These test-mode rules expired on ${expires.toISOString().slice(0, 10)}, so every request is denied right now. Do not "fix" it by moving the date: ` +
                `write real rules (signed-in owner only) instead.`,
          "request.time < timestamp.date(...)",
          snippet,
        ),
      );
      continue;
    }

    // A rule that never looks at request.auth: whoever can reach the database may do it, signed in or not. Validating
    // the shape of the data (hasOnly, size limits) is not an access check.
    const conditionPicture = withCalledFunctions(rawCondition, functions);
    if (
      modifies.length > 0 &&
      condition !== "false" &&
      !/request\.auth/.test(conditionPicture) &&
      !/\b(?:get|exists|getAfter|existsAfter)\s*\(/.test(conditionPicture)
    ) {
      findings.push(
        makeFinding(
          file,
          line,
          isGlobal ? "critical" : "high",
          "medium",
          `Nothing in this rule checks who is asking: any visitor on the internet, signed in or not, can ${modifies.join(" or ")} ${where}` +
            `${piiFields.length > 0 ? ` (fields such as ${piiFields.join(", ")})` : ""}. Checking the shape of the data does not protect it. ` +
            `Require a signed-in owner (request.auth.uid == resource.data.ownerId), or an admin check, for every ${modifies.join("/")}.`,
          "no request.auth in the rule",
          snippet,
        ),
      );
      continue;
    }

    if (isSignedInOnly(condition)) {
      if (modifies.length > 0) {
        findings.push(
          makeFinding(
            file,
            line,
            isGlobal ? "critical" : "high",
            "medium",
            `This rule only checks that the caller is signed in. Any signed-in user — including anonymous sign-ins anyone can create — can ${modifies.join(" or ")} ${where}, ` +
              `not just their own. Compare the ${noun}'s owner with the caller: request.auth.uid == resource.data.ownerId (or the {userId} in the path).`,
            "request.auth != null",
            snippet,
          ),
        );
      } else if (reads && (isGlobal || sensitive)) {
        findings.push(
          makeFinding(
            file,
            line,
            isGlobal && kind !== "storage" ? "high" : "medium",
            "medium",
            `This rule lets any signed-in user (anonymous sign-ins included) read ${where}${sensitive && !isGlobal ? ", which looks like private data" : ""}. ` +
              `Limit reads to the owner: request.auth.uid == resource.data.ownerId.`,
            "request.auth != null",
            snippet,
          ),
        );
      }
    }
  }
  return findings;
}

type RtdbVerdict = "open" | "signed-in" | "other";

function rtdbVerdict(value: unknown): RtdbVerdict {
  if (value === true) return "open";
  if (typeof value !== "string") return "other";
  const v = value.replace(/\s+/g, "");
  if (v === "true") return "open";
  if (v === "auth!=null") return "signed-in";
  return "other";
}

/** Checks a Realtime Database `database.rules.json`. */
export function analyzeRealtimeDatabaseRules(source: string, file: string): Finding[] {
  let parsed: unknown;
  try {
    parsed = JSON.parse(source);
  } catch {
    return [];
  }
  const rules = (parsed as { rules?: unknown }).rules;
  if (typeof rules !== "object" || rules === null) return [];

  // `.read` / `.write` keys appear in the text in the same order JSON.parse visits them.
  const positions = [...source.matchAll(/"\.(read|write)"\s*:/g)].map((m) => lineAt(source, m.index ?? 0));
  let visit = 0;
  const findings: Finding[] = [];

  const walk = (node: Record<string, unknown>, path: string[]): void => {
    for (const [key, value] of Object.entries(node)) {
      if (key === ".read" || key === ".write") {
        const line = positions[visit++] ?? 1;
        const verdict = rtdbVerdict(value);
        const where = path.length === 0 ? "the ENTIRE database" : `/${path.join("/")}`;
        const sensitive = path.some((p) => SENSITIVE_PATH.test(p));
        const kind = key === ".write" ? "write" : "read";
        const snippet = `"${key}": ${JSON.stringify(value)}`;
        if (verdict === "open" && (kind === "write" || path.length === 0 || sensitive)) {
          findings.push(
            makeFinding(
              file,
              line,
              // a public database with writes closed is exposure, not takeover; a public chat is a design choice
              kind === "write" ? "critical" : path.length === 0 || path.some((p) => PII_PATH.test(p)) ? "high" : "medium",
              "high",
              `This rule lets ANYONE on the internet ${kind} ${where}. Your Firebase config is public by design, so nothing else protects it. ` +
                `Require the owner: "${key}": "auth != null && auth.uid === $uid".`,
              `${key}: true`,
              snippet,
            ),
          );
        } else if (verdict === "signed-in" && (kind === "write" || path.length === 0 || sensitive)) {
          findings.push(
            makeFinding(
              file,
              line,
              kind === "write" || path.length === 0 ? "high" : "medium",
              "medium",
              `This rule only checks that the caller is signed in (anonymous sign-ins included): any user can ${kind} ${where}, not just their own data. ` +
                `Tie it to the owner: "${key}": "auth != null && auth.uid === $uid".`,
              `${key}: auth != null`,
              snippet,
            ),
          );
        }
      } else if (!key.startsWith(".") && typeof value === "object" && value !== null) {
        walk(value as Record<string, unknown>, [...path, key]);
      }
    }
  };
  walk(rules as Record<string, unknown>, []);
  return findings;
}
