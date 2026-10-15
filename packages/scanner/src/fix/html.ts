import { SyntaxNode, findNodes } from "../parsers/utils";
import { TextEdit } from "./types";

/**
 * Mechanical fixes for `xss` and `open-redirect`:
 *  - `res.send(\`<p>${q}</p>\`)`          -> `${escapeHtml(q)}` (and `"<p>" + q`, and `res.send(q)`)
 *  - `res.redirect(next)`                  -> `res.redirect(safeRedirect(next))`: only a same-site path survives, else "/"
 *
 * Each fix wraps the value the scan named, adds a small helper to the end of the file when it is not defined yet, and never
 * touches anything else. A value that reached the sink through a variable is wrapped where the sink uses it.
 */

const ESCAPE_HELPER = `
function escapeHtml(value: unknown): string {
  return String(value).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c] as string);
}
`;
const ESCAPE_HELPER_JS = `
function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
}
`;
const REDIRECT_HELPER = `
// Only a path on this site is allowed: "/dashboard" is, "//evil.com", "https://evil.com" and "/\\\\evil.com" are not.
function safeRedirect(target: unknown, fallback = "/"): string {
  return typeof target === "string" && /^\\/(?![/\\\\])/.test(target) ? target : fallback;
}
`;
const REDIRECT_HELPER_JS = `
// Only a path on this site is allowed: "/dashboard" is, "//evil.com", "https://evil.com" and "/\\\\evil.com" are not.
function safeRedirect(target, fallback = "/") {
  return typeof target === "string" && /^\\/(?![/\\\\])/.test(target) ? target : fallback;
}
`;

/** The call or `new` expression that starts exactly at (line, column) (1-based), if there is one. */
export function sinkAt(root: SyntaxNode, line: number, column: number): SyntaxNode | undefined {
  return findNodes(root, (n) => (n.type === "call_expression" || n.type === "new_expression") && n.startPosition.row + 1 === line && n.startPosition.column + 1 === column)[0];
}

/** `User-controlled input ('req.query.q') flows ...`: the text the scan says reached the sink. */
export function viaOf(message: string): string | undefined {
  return /User-controlled input \('([^']+)'\)/.exec(message)?.[1];
}

/** The places inside `argument` where the value is used on its own: the argument itself, a `${...}`, an operand of `+`. */
function directUses(argument: SyntaxNode, via: string): SyntaxNode[] {
  const uses: SyntaxNode[] = [];
  const visit = (node: SyntaxNode): void => {
    if (node.text === via && (node.type === "identifier" || node.type === "member_expression" || node.type === "subscript_expression")) {
      uses.push(node);
      return;
    }
    if (node.type === "template_string") {
      for (const part of node.namedChildren) if (part.type === "template_substitution") for (const inner of part.namedChildren) visit(inner);
    } else if (node.type === "binary_expression" && node.childForFieldName("operator")?.text === "+") {
      for (const side of ["left", "right"] as const) {
        const child = node.childForFieldName(side);
        if (child) visit(child);
      }
    } else if (node.type === "parenthesized_expression" || node.type === "await_expression") {
      const inner = node.namedChild(0);
      if (inner) visit(inner);
    }
  };
  visit(argument);
  return uses;
}

function helperEdit(file: string, source: string, name: "escapeHtml" | "safeRedirect", isTypeScript: boolean): TextEdit | undefined {
  if (new RegExp(`\\b${name}\\b`).test(source)) return undefined; // already defined or imported: use it
  const text = name === "escapeHtml" ? (isTypeScript ? ESCAPE_HELPER : ESCAPE_HELPER_JS) : isTypeScript ? REDIRECT_HELPER : REDIRECT_HELPER_JS;
  const end = source.length;
  const separator = source.endsWith("\n") ? "" : "\n";
  return { file, start: end, end, text: separator + text, note: `added the small ${name}() helper at the end of the file` };
}

/** The first argument of the call that uses `via` directly (`res.redirect(302, url)` has the target second). */
function argumentUsing(sink: SyntaxNode, via: string): { argument: SyntaxNode; uses: SyntaxNode[] } | undefined {
  for (const argument of sink.childForFieldName("arguments")?.namedChildren ?? []) {
    const uses = directUses(argument, via);
    if (uses.length > 0) return { argument, uses };
  }
  return undefined;
}

export interface HtmlFix {
  edits: TextEdit[];
}

/** Wraps the value in `escapeHtml(...)` where the response body uses it. */
export function escapeEdits(sink: SyntaxNode, via: string, file: string, source: string, isTypeScript: boolean): HtmlFix | { reason: string } {
  const found = argumentUsing(sink, via);
  const uses = found?.uses ?? [];
  if (uses.length === 0) return { reason: `the value (${via}) is not used on its own in the response (it is passed through another call), so it cannot be wrapped safely` };
  const edits: TextEdit[] = uses.map((use) => ({ file, start: use.startIndex, end: use.endIndex, text: `escapeHtml(${use.text})`, note: `escaped ${use.text} before it goes into the HTML` }));
  const helper = helperEdit(file, source, "escapeHtml", isTypeScript);
  return { edits: helper ? [...edits, helper] : edits };
}

/** Wraps the redirect target in `safeRedirect(...)`. */
export function redirectEdits(sink: SyntaxNode, via: string, file: string, source: string, isTypeScript: boolean): HtmlFix | { reason: string } {
  // `redirect(next)` / `res.redirect(req.query.url)`: the whole target is the value. A template such as `${origin}${next}`
  // is wrapped around the value only: the part before it stays as written.
  const found = argumentUsing(sink, via);
  const argument = found?.argument as SyntaxNode;
  const uses = found?.uses ?? [];
  if (uses.length === 0) return { reason: `the redirect target is built from ${via} through another call, so it cannot be wrapped safely` };
  const isWhole = uses.length === 1 && (uses[0] as SyntaxNode).id === argument.id;
  const edits: TextEdit[] = uses.map((use) => ({
    file,
    start: use.startIndex,
    end: use.endIndex,
    text: `safeRedirect(${use.text})`,
    note: isWhole ? `the redirect target ${use.text} must now be a path on this site, else "/"` : `${use.text} in the redirect URL must now be a path on this site, else "/"`,
  }));
  const helper = helperEdit(file, source, "safeRedirect", isTypeScript);
  return { edits: helper ? [...edits, helper] : edits };
}
