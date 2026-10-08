import { Finding, Severity } from "../types";

/**
 * Firebase security rules are the only thing between the internet and your database: the Firebase
 * config (apiKey, projectId, ...) is public by design and ships in every browser bundle, so anyone can talk
 * to Firestore, Storage and the Realtime Database directly. `allow read, write: if true;` (or the console's
 * "test mode" default, `if request.time < timestamp.date(...)`) therefore means "the whole database belongs
 * to whoever finds the project id".
 */

const SENSITIVE_PATH = /user|profile|customer|order|payment|invoice|message|chat|account|subscription|private|secret|token|member|patient|kyc|billing|admin|session/i;

type Method = "get" | "list" | "create" | "update" | "delete";

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
    .replace(/request\.auth\.token\.email_verified==true/g, "")
    .replace(/request\.auth\.token\.firebase\.sign_in_provider!='anonymous'/g, "")
    .replace(/[&()]/g, "");
  return c.includes("request.auth!=null") && rest === "";
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
  const store = kind === "storage" ? "Cloud Storage" : "Firestore";
  const noun = kind === "storage" ? "file" : "document";
  const token = /\bmatch\s+((?:[^\s{};]|\{[^{}]*\})+)\s*\{|\bfunction\s+\w+\s*\([^)]*\)\s*\{|\ballow\s+([\w\s,]+?)\s*(?::\s*if\s+([^;]*))?;|\{|\}/g;

  for (let m = token.exec(text); m !== null; m = token.exec(text)) {
    if (m[0] === "}") {
      frames.pop();
      continue;
    }
    if (m[0].startsWith("match")) {
      frames.push((m[1] as string).trim());
      continue;
    }
    if (m[0].startsWith("function") || m[0] === "{") {
      frames.push("");
      continue;
    }

    // allow <methods> [: if <condition>];
    const methods = expandMethods(m[2] as string);
    const writes = (["create", "update", "delete"] as const).filter((x) => methods.has(x));
    const modifies = (["update", "delete"] as const).filter((x) => methods.has(x));
    const reads = methods.has("get") || methods.has("list");
    const condition = m[3] === undefined ? "true" : unwrap(m[3]);
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
      } else if (reads && (isGlobal || sensitive)) {
        findings.push(
          makeFinding(
            file,
            line,
            isGlobal ? "critical" : "high",
            "high",
            `This rule lets ANYONE on the internet read ${where}${sensitive && !isGlobal ? ", which looks like private data" : ""} (\`if true\`). ` +
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
            isGlobal ? "high" : "medium",
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
              kind === "write" || path.length === 0 ? "critical" : "high",
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
