import { Finding, VulnerabilityType } from "./types";

/**
 * Ways to tell the scanner "I looked at this, it's fine":
 *  - an inline comment on (or directly above) the flagged line;
 *  - path patterns (`.security-hub-ignore`, `--ignore`) for whole files and folders.
 *
 * A scanner people can't quiet gets uninstalled the first time it is wrong, so these
 * are part of the product — and they are counted and reported, never silent.
 */

export const RULE_IDS: readonly VulnerabilityType[] = [
  "sql-injection",
  "xss",
  "command-injection",
  "path-traversal",
  "csrf",
  "ssrf",
  "idor",
  "broken-access-control",
  "insecure-role-assignment",
  "insecure-file-upload",
  "username-enumeration",
  "code-injection",
  "open-redirect",
  "nosql-injection",
  "insecure-deserialization",
  "xxe",
];

// `// security-hub-ignore`, `/* security-hub-ignore */`, `// security-hub-ignore sql-injection, xss -- reason`
const DIRECTIVE = /(?:\/\/|\/\*|\*)\s*security-hub-ignore\b([^\n]*)/;

/** Rule ids named by a directive; empty array = the directive covers every rule. */
function directiveRules(rest: string): VulnerabilityType[] {
  const withoutReason = rest.split("--")[0] ?? "";
  const tokens = withoutReason.replace(/\*\/.*/, "").split(/[\s,:]+/).filter(Boolean);
  return tokens.filter((t): t is VulnerabilityType => (RULE_IDS as readonly string[]).includes(t));
}

function suppressedBy(line: string | undefined, ruleId: VulnerabilityType, mustBeCommentLine: boolean): boolean {
  if (line === undefined) return false;
  // The line above only counts when it is just a comment — otherwise a trailing
  // `// security-hub-ignore` on unrelated code would silently cover the next line too.
  if (mustBeCommentLine && !/^\s*(\/\/|\/\*|\*)/.test(line)) return false;
  const match = DIRECTIVE.exec(line);
  if (!match) return false;
  const rules = directiveRules(match[1] ?? "");
  return rules.length === 0 || rules.includes(ruleId);
}

export function applyInlineSuppressions(
  findings: Finding[],
  sourceCode: string,
): { kept: Finding[]; suppressed: number } {
  if (findings.length === 0 || !sourceCode.includes("security-hub-ignore")) return { kept: findings, suppressed: 0 };
  const lines = sourceCode.split(/\r?\n/);
  const kept = findings.filter((finding) => {
    const index = finding.location.startLine - 1;
    return !(suppressedBy(lines[index], finding.ruleId, false) || suppressedBy(lines[index - 1], finding.ruleId, true));
  });
  return { kept, suppressed: findings.length - kept.length };
}

// ---- path patterns (gitignore-style, the small useful subset) ------------

function globToRegExp(raw: string): RegExp | undefined {
  let pattern = raw.trim();
  if (pattern === "" || pattern.startsWith("#")) return undefined;
  const anchored = pattern.startsWith("/");
  if (anchored) pattern = pattern.slice(1);
  const directoryOnly = pattern.endsWith("/");
  if (directoryOnly) pattern = pattern.slice(0, -1);
  if (pattern === "") return undefined;
  const hasSlash = pattern.includes("/");

  let source = "";
  for (let i = 0; i < pattern.length; i++) {
    const ch = pattern[i] as string;
    if (ch === "*" && pattern[i + 1] === "*") {
      if (pattern[i + 2] === "/") {
        source += "(?:.*/)?";
        i += 2;
      } else {
        source += ".*";
        i += 1;
      }
    } else if (ch === "*") {
      source += "[^/]*";
    } else if (ch === "?") {
      source += "[^/]";
    } else {
      source += ch.replace(/[.+^${}()|[\]\\]/g, "\\$&");
    }
  }
  // A pattern with no slash matches at any depth (`*.generated.ts`, `fixtures`),
  // otherwise it is relative to the scan root. A match covers everything beneath it.
  const prefix = hasSlash || anchored ? "^" : "^(?:.*/)?";
  const suffix = directoryOnly ? "/.*$" : "(?:/.*)?$";
  return new RegExp(prefix + source + suffix);
}

/** Parses the contents of a `.security-hub-ignore` file. */
export function parseIgnoreFile(text: string): string[] {
  return text
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line !== "" && !line.startsWith("#"));
}

/** Returns a predicate over scan-root-relative paths (forward slashes). */
export function compileIgnorePatterns(patterns: string[]): (relativePath: string) => boolean {
  const expressions = patterns.map(globToRegExp).filter((r): r is RegExp => r !== undefined);
  if (expressions.length === 0) return () => false;
  return (relativePath) => expressions.some((expression) => expression.test(relativePath));
}
