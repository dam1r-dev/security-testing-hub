import { SyntaxNode, findNodes } from "../parsers/utils";
import { TextEdit } from "./types";

/**
 * Moves a secret out of the source into an environment variable:
 *
 *   const API_KEY = "sk_live_...";                    ->  const API_KEY = process.env.API_KEY;
 *   jwt.sign(data, "my-secret")                       ->  jwt.sign(data, process.env.JWT_SECRET)
 *   apiKey: process.env.KEY || "sk_live_..."          ->  apiKey: process.env.KEY
 *
 * The VALUE goes to .env (which is added to .gitignore), the NAME to .env.example. The old value stays in the git
 * history, so the caller is always told to rotate it.
 */

const WRAPPERS = new Set(["parenthesized_expression", "as_expression", "satisfies_expression", "non_null_expression", "await_expression"]);

export interface SecretFix {
  edit: TextEdit;
  name: string;
  /** The literal's text content when it can be written to .env as it is; undefined when it needs a person. */
  value: string | undefined;
}

/** Offset of (line, column), both 1-based, in `source`. */
export function offsetOf(source: string, line: number, column: number): number {
  let offset = 0;
  for (let i = 1; i < line; i++) {
    const next = source.indexOf("\n", offset);
    if (next === -1) return -1;
    offset = next + 1;
  }
  return offset + column - 1;
}

function toEnvName(raw: string): string {
  const last = raw.split(/[.[\]]/).filter(Boolean).pop() ?? raw;
  return last
    .replace(/["'`]/g, "")
    .replace(/([a-z0-9])([A-Z])/g, "$1_$2")
    .replace(/[^A-Za-z0-9]+/g, "_")
    .replace(/^_+|_+$/g, "")
    .toUpperCase();
}

function literalValue(node: SyntaxNode): string | undefined {
  if (node.type === "string") return node.text.slice(1, -1);
  if (node.type === "template_string" && !node.namedChildren.some((c) => c.type === "template_substitution")) return node.text.slice(1, -1);
  return undefined;
}

/** What the literal is called: a variable, a property, or the role of the call it is an argument of. */
function nameFor(literal: SyntaxNode): string {
  let current = literal;
  for (;;) {
    const parent = current.parent;
    if (!parent) return "SECRET";
    const isFallback = parent.type === "binary_expression" && /^(\|\||\?\?)$/.test(parent.childForFieldName("operator")?.text ?? "");
    if (WRAPPERS.has(parent.type) || isFallback) {
      current = parent;
      continue;
    }
    const valueOf = (field: string): boolean => parent.childForFieldName(field)?.id === current.id;
    if (parent.type === "arguments") {
      const callee = parent.parent?.childForFieldName("function")?.text ?? "";
      if (/jwt|jsonwebtoken|\.sign$|^sign$|\.verify$|^verify$/i.test(callee)) return "JWT_SECRET";
      return "SECRET";
    }
    let name: string | undefined;
    if (parent.type === "pair" && valueOf("value")) name = parent.childForFieldName("key")?.text;
    else if (parent.type === "variable_declarator" && valueOf("value")) name = parent.childForFieldName("name")?.text;
    else if (parent.type === "assignment_expression" && valueOf("right")) name = parent.childForFieldName("left")?.text;
    else if ((parent.type === "public_field_definition" || parent.type === "field_definition") && valueOf("value")) {
      name = (parent.childForFieldName("property") ?? parent.childForFieldName("name"))?.text;
    }
    if (!name) return "SECRET";
    const base = toEnvName(name);
    // a bare `secret` / `key` / `password` is named by the call it configures: session({ secret }) -> SESSION_SECRET
    if (/^(?:SECRET|KEY|PASSWORD|TOKEN)$/.test(base) && parent.type === "pair") {
      const call = parent.parent?.parent?.parent;
      const callee = call?.type === "call_expression" ? (call.childForFieldName("function")?.text ?? "") : "";
      const role = /session/i.test(callee) ? "SESSION" : /jwt|sign/i.test(callee) ? "JWT" : /cookie/i.test(callee) ? "COOKIE" : /csrf/i.test(callee) ? "CSRF" : "";
      if (role) return `${role}_${base}`;
    }
    return base || "SECRET";
  }
}

/** Fix for the string literal that starts at `offset`: `process.env.NAME` in its place. */
export function secretFix(root: SyntaxNode, file: string, offset: number, isTypeScript: boolean, taken: Map<string, string>): SecretFix | { reason: string } {
  const candidates = findNodes(root, (n) => (n.type === "string" || n.type === "template_string") && n.startIndex <= offset && n.endIndex > offset);
  // the innermost literal that holds the secret
  const literal = candidates.sort((a, b) => b.startIndex - a.startIndex)[0];
  if (!literal) return { reason: "the secret is not a plain string literal (it may be in a comment or built at run time)" };
  const value = literalValue(literal);
  if (value === undefined || value === "") return { reason: "the value is not a plain string" };

  let name = nameFor(literal);
  // two different secrets must not share one variable name
  let n = 1;
  while (taken.has(name) && taken.get(name) !== value) name = `${name.replace(/_\d+$/, "")}_${++n}`;
  taken.set(name, value);

  // `process.env.X || "literal"`: drop the fallback instead of nesting
  const parent = literal.parent;
  if (parent?.type === "binary_expression" && /^(\|\||\?\?)$/.test(parent.childForFieldName("operator")?.text ?? "")) {
    const left = parent.childForFieldName("left");
    const right = parent.childForFieldName("right");
    if (right?.id === literal.id && left && /process\.env\.|import\.meta\.env\./.test(left.text)) {
      return {
        edit: { file, start: parent.startIndex, end: parent.endIndex, text: isTypeScript && /^process\.env\.\w+$/.test(left.text) ? `${left.text}!` : left.text, note: `removed the hard-coded fallback for ${left.text}`, secret: value },
        name: /process\.env\.(\w+)/.exec(left.text)?.[1] ?? name,
        value,
      };
    }
  }

  const reference = `process.env.${name}${isTypeScript ? "!" : ""}`;
  const plainValue = /[\\\r\n]/.test(value) ? undefined : value;
  return { edit: { file, start: literal.startIndex, end: literal.endIndex, text: reference, note: `reads the secret from the ${name} environment variable instead of the source code`, secret: value }, name, value: plainValue };
}

/** A `.env` line for a value: quoted when it has characters a dotenv parser would misread. */
export function envLine(name: string, value: string): string {
  return /^[\w@%+=:,./-]*$/.test(value) ? `${name}=${value}` : `${name}="${value.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
}
