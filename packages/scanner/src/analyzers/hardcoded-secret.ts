import { ParsedFile } from "../parsers/ast-parser";
import { SyntaxNode, findNodes } from "../parsers/utils";
import {
  findKnownSecrets,
  isPlaceholder,
  isPublicEnvSecretName,
  isSensitiveName,
  isSigningSecretName,
  looksLikeSecret,
  normalizeName,
  redact,
} from "../secrets/detect";
import { Finding, Severity } from "../types";
import { Analyzer } from "./base-analyzer";

const ROTATE =
  "Treat it as already leaked: revoke / rotate it now (removing the line is not enough — it stays in the git history), " +
  "then load the new value from an environment variable or a secret manager and keep it out of the repository.";

const WRAPPERS = new Set(["parenthesized_expression", "as_expression", "satisfies_expression", "non_null_expression", "await_expression"]);

class LineIndex {
  private readonly starts: number[] = [0];

  constructor(private readonly text: string) {
    for (let i = 0; i < text.length; i++) if (text.charCodeAt(i) === 10) this.starts.push(i + 1);
  }

  /** 1-based line and column of a character offset. */
  position(offset: number): { line: number; column: number } {
    let low = 0;
    let high = this.starts.length - 1;
    while (low < high) {
      const mid = (low + high + 1) >> 1;
      if ((this.starts[mid] as number) <= offset) low = mid;
      else high = mid - 1;
    }
    return { line: low + 1, column: offset - (this.starts[low] as number) + 1 };
  }

  lineText(line: number): string {
    const start = this.starts[line - 1] ?? 0;
    const end = this.starts[line] ?? this.text.length;
    return this.text.slice(start, end).replace(/\r?\n$/, "");
  }
}

/** The name a string literal is being given: `{ apiKey: "..." }`, `const token = "..."`, `x.secret = process.env.S || "..."`. */
function nameFor(literal: SyntaxNode): string | undefined {
  let current = literal;
  for (;;) {
    const parent = current.parent;
    if (!parent) return undefined;
    const isFallback =
      parent.type === "binary_expression" && /^(\|\||\?\?)$/.test(parent.childForFieldName("operator")?.text ?? "");
    if (WRAPPERS.has(parent.type) || isFallback) {
      current = parent;
      continue;
    }
    const valueOf = (field: string): boolean => parent.childForFieldName(field)?.id === current.id;
    if (parent.type === "pair" && valueOf("value")) return parent.childForFieldName("key")?.text.replace(/^["'`]|["'`]$/g, "");
    if (parent.type === "variable_declarator" && valueOf("value")) return parent.childForFieldName("name")?.text;
    if (parent.type === "assignment_expression" && valueOf("right")) return parent.childForFieldName("left")?.text;
    if ((parent.type === "public_field_definition" || parent.type === "field_definition") && valueOf("value")) {
      return (parent.childForFieldName("property") ?? parent.childForFieldName("name"))?.text;
    }
    return undefined;
  }
}

function literalValue(node: SyntaxNode): string | undefined {
  if (node.type === "string") return node.text.slice(1, -1);
  if (node.type === "template_string" && !node.namedChildren.some((c) => c.type === "template_substitution")) {
    return node.text.slice(1, -1);
  }
  return undefined;
}

/** Is this literal an object property of an object passed straight to a call, e.g. session({ secret: "..." })? */
function isCallOptionsProperty(literal: SyntaxNode): boolean {
  const pair = literal.parent;
  return pair?.type === "pair" && pair.parent?.type === "object" && pair.parent.parent?.type === "arguments";
}

const PUBLIC_ENV_USE = /(?:process\.env|import\.meta\.env)\.([A-Z][A-Z0-9_]*)/g;
const SIGNING_CALL = /^(?:jwt|jsonwebtoken)\.(?:sign|verify)$/;

/**
 * Secrets typed into the source: provider tokens by their shape, credentials assigned to
 * `password` / `apiKey` / `token` names, guessable signing secrets (`jwt.sign(x, "secret")`,
 * `session({ secret: "keyboard cat" })`), and secrets placed in browser-exposed env variables
 * (`NEXT_PUBLIC_..._SECRET`). Never prints a secret in full.
 */
export class HardcodedSecretAnalyzer implements Analyzer {
  analyze(parsed: ParsedFile, filePath: string): Finding[] {
    const text = parsed.sourceCode;
    const index = new LineIndex(text);
    const findings: Finding[] = [];
    const covered: Array<[number, number]> = [];
    const reportedKeys = new Set<string>();

    const add = (
      start: number,
      end: number,
      secret: string,
      severity: Severity,
      confidence: Finding["confidence"],
      message: string,
      isSecret = true,
    ): void => {
      const key = `${start}:${end}`;
      if (reportedKeys.has(key)) return;
      reportedKeys.add(key);
      covered.push([start, end]);
      const from = index.position(start);
      const to = index.position(Math.max(start, end - 1));
      const lineText = index.lineText(from.line).trim();
      const shown = isSecret ? lineText.split(secret).join("<redacted>") : lineText;
      findings.push({
        ruleId: "hardcoded-secret",
        severity,
        confidence,
        message,
        location: { file: filePath, startLine: from.line, startColumn: from.column, endLine: to.line, endColumn: to.column + 1 },
        sourceSnippet: isSecret ? redact(secret) : secret,
        sinkSnippet: shown.length > 160 ? `${shown.slice(0, 157)}...` : shown,
      });
    };
    const isCovered = (node: SyntaxNode): boolean =>
      covered.some(([from, to]) => node.startIndex < to && node.endIndex > from);

    // 1. Known token formats anywhere in the file, comments included.
    for (const match of findKnownSecrets(text)) {
      add(
        match.index,
        match.index + match.text.length,
        match.text,
        match.secret.severity,
        "high",
        `A ${match.secret.label} is written into the source code (${redact(match.text)}). Anyone who can read this ` +
          `repository can use it. ${ROTATE}`,
      );
    }

    // 2. Browser-exposed environment variables that carry a secret.
    PUBLIC_ENV_USE.lastIndex = 0;
    for (let m = PUBLIC_ENV_USE.exec(text); m !== null; m = PUBLIC_ENV_USE.exec(text)) {
      const name = m[1] as string;
      if (!isPublicEnvSecretName(name)) continue;
      // A mention in a comment (documentation, examples) is not a use of the variable.
      const lineStart = text.lastIndexOf("\n", m.index) + 1;
      const before = text.slice(lineStart, m.index);
      if (/^\s*(\/\/|\/\*|\*)/.test(before) || before.includes("//")) continue;
      add(
        m.index,
        m.index + m[0].length,
        name,
        "high",
        "high",
        `${name} is read as a browser-exposed variable: its prefix makes the build copy the value into the JavaScript ` +
          `every visitor downloads, so a secret in it is public. Rename it without the public prefix and use it only in ` +
          `server code (API routes, server actions), and rotate the value you already shipped.`,
        false, // the variable NAME is shown, not a secret value
      );
    }

    // 3. String literals: signing secrets, credentials by name.
    const strings = findNodes(parsed.tree.rootNode, (n) => n.type === "string" || n.type === "template_string");
    for (const node of strings) {
      if (isCovered(node)) continue;
      const value = literalValue(node);
      if (value === undefined || value === "") continue;

      // jwt.sign(payload, "literal") / jwt.verify(token, "literal")
      const call = node.parent?.type === "arguments" ? node.parent.parent : undefined;
      if (call?.type === "call_expression") {
        const callee = call.childForFieldName("function")?.text ?? "";
        const isSecretArgument = call.childForFieldName("arguments")?.namedChild(1)?.id === node.id;
        if (SIGNING_CALL.test(callee) && isSecretArgument && !/BEGIN (PUBLIC KEY|CERTIFICATE)/.test(value)) {
          add(
            node.startIndex,
            node.endIndex,
            value,
            "high",
            "high",
            `The secret passed to ${callee}() is a string written in the code (${redact(value)}). Anyone who reads the ` +
              `code can forge valid tokens and log in as any user. Use a long random value from an environment variable.`,
          );
          continue;
        }
      }

      const rawName = nameFor(node);
      if (!rawName) continue;
      const name = normalizeName(rawName);

      if (isSigningSecretName(name) && (name !== "secret" || isCallOptionsProperty(node)) && value.length >= 4) {
        add(
          node.startIndex,
          node.endIndex,
          value,
          "high",
          "high",
          `\`${rawName}\` is a string written in the code (${redact(value)}) and is used to sign tokens or sessions` +
            `${isPlaceholder(value) ? " (it looks like a placeholder that was never replaced)" : ""}. Anyone who reads the ` +
            `code can forge logins. Use a long random value from an environment variable (process.env.${name.toUpperCase()}).`,
        );
      } else if (isSensitiveName(name) && looksLikeSecret(value)) {
        add(
          node.startIndex,
          node.endIndex,
          value,
          "high",
          "medium",
          `\`${rawName}\` is assigned a string that looks like a real credential (${redact(value)}). ${ROTATE}`,
        );
      }
    }

    return findings;
  }
}
