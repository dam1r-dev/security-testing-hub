import { SyntaxNode, findNodes } from "../parsers/utils";
import { TextEdit } from "./types";

/**
 * Mechanical fixes for `insecure-jwt` and `insecure-cors`:
 *  - sign without an expiry            -> add { expiresIn: "1h" } (or .setExpirationTime("1h") for jose)
 *  - algorithms: [..., "none"]         -> drop "none"
 *  - algorithm: "none"                 -> "HS256"
 *  - ignoreExpiration: true            -> removed
 *  - cors({ origin: true, ... })       -> origin from the ALLOWED_ORIGINS environment variable
 */

const EXPIRY = "1h";

function objectPair(object: SyntaxNode, key: string): SyntaxNode | undefined {
  return object.namedChildren.find((c) => c.type === "pair" && c.childForFieldName("key")?.text.replace(/^["'`]|["'`]$/g, "") === key);
}

/** The range that removes `node` from a comma-separated list, with one adjacent comma. */
function removalRange(node: SyntaxNode, siblings: SyntaxNode[], source: string): { start: number; end: number } {
  const index = siblings.findIndex((s) => s.id === node.id);
  const next = siblings[index + 1];
  const previous = siblings[index - 1];
  if (next) return { start: node.startIndex, end: next.startIndex };
  if (previous) return { start: previous.endIndex, end: node.endIndex };
  // the only item: take a trailing comma too
  const trailing = /^\s*,/.exec(source.slice(node.endIndex));
  return { start: node.startIndex, end: node.endIndex + (trailing ? trailing[0].length : 0) };
}

/** The `jwt.sign(...)` / `new SignJWT(...).sign(...)` call at a finding, fixed to expire. */
export function expiryEdit(call: SyntaxNode, file: string, source: string): TextEdit | { reason: string } {
  const callee = call.childForFieldName("function");
  const args = call.childForFieldName("arguments")?.namedChildren.filter((a) => a.type !== "comment") ?? [];
  if (callee?.type === "member_expression" && /\bnew\s+SignJWT\b/.test(callee.text)) {
    const property = callee.childForFieldName("property");
    if (!property) return { reason: "cannot find where the chain calls .sign()" };
    const dot = source.lastIndexOf(".", property.startIndex);
    return { file, start: dot, end: dot, text: `.setExpirationTime("${EXPIRY}")`, note: `added .setExpirationTime("${EXPIRY}") so the token expires` };
  }
  if (args.length === 2) {
    const last = args[1] as SyntaxNode;
    return { file, start: last.endIndex, end: last.endIndex, text: `, { expiresIn: "${EXPIRY}" }`, note: `added { expiresIn: "${EXPIRY}" } so the token expires` };
  }
  const options = args[2];
  if (args.length === 3 && options?.type === "object") {
    const open = options.startIndex + 1;
    const empty = options.namedChildren.length === 0;
    return { file, start: open, end: open, text: empty ? ` expiresIn: "${EXPIRY}" ` : ` expiresIn: "${EXPIRY}",`, note: `added expiresIn: "${EXPIRY}" to the options so the token expires` };
  }
  return { reason: "the options are not a plain object written out in the call" };
}

/** `verify(..., { algorithms: [...,"none"] })`, `sign(..., { algorithm: "none" })`, `ignoreExpiration: true`. */
export function jwtOptionEdits(call: SyntaxNode, file: string, source: string): TextEdit[] {
  const edits: TextEdit[] = [];
  const options = call.childForFieldName("arguments")?.namedChildren.filter((a) => a.type !== "comment")[2];
  if (options?.type !== "object") return edits;

  const algorithms = objectPair(options, "algorithms")?.childForFieldName("value");
  if (algorithms?.type === "array") {
    const elements = algorithms.namedChildren.filter((e) => e.type !== "comment");
    const none = elements.find((e) => /^["'`]none["'`]$/i.test(e.text));
    if (none) {
      if (elements.length === 1) edits.push({ file, start: none.startIndex, end: none.endIndex, text: '"HS256"', note: 'replaced the "none" algorithm with "HS256"' });
      else {
        const range = removalRange(none, elements, source);
        edits.push({ file, ...range, text: "", note: 'removed "none" from the accepted algorithms' });
      }
    }
  }
  const algorithm = objectPair(options, "algorithm")?.childForFieldName("value");
  if (algorithm && /^["'`]none["'`]$/i.test(algorithm.text)) {
    edits.push({ file, start: algorithm.startIndex, end: algorithm.endIndex, text: '"HS256"', note: 'replaced algorithm "none" with "HS256"' });
  }
  const ignore = objectPair(options, "ignoreExpiration");
  if (ignore?.childForFieldName("value")?.text === "true") {
    const pairs = options.namedChildren.filter((c) => c.type === "pair" || c.type === "shorthand_property_identifier" || c.type === "spread_element");
    const range = removalRange(ignore, pairs, source);
    edits.push({ file, ...range, text: "", note: "removed ignoreExpiration: true so expired tokens are rejected" });
  }
  return edits;
}

/** `cors({ origin: true, credentials: true })` -> the origins come from ALLOWED_ORIGINS (comma separated). */
export function corsEdit(call: SyntaxNode, file: string): TextEdit | { reason: string } {
  const options = call.childForFieldName("arguments")?.namedChildren.find((a) => a.type === "object");
  const origin = options ? objectPair(options, "origin")?.childForFieldName("value") : undefined;
  if (!origin) return { reason: "the origin option is not written out as a plain property" };
  if (origin.type !== "true" && origin.type !== "regex" && origin.type !== "arrow_function" && origin.type !== "function_expression") {
    return { reason: "the origin option is not a form the fixer knows (true, a catch-all regex, an allow-all callback)" };
  }
  return {
    file,
    start: origin.startIndex,
    end: origin.endIndex,
    text: '(process.env.ALLOWED_ORIGINS ?? "").split(",").filter(Boolean)',
    note: "the allowed origins now come from the ALLOWED_ORIGINS environment variable instead of accepting every origin",
  };
}

/** Finds the call expression that starts exactly at (line, column) (1-based), if there is one. */
export function callAt(root: SyntaxNode, line: number, column: number): SyntaxNode | undefined {
  return findNodes(root, (n) => n.type === "call_expression" && n.startPosition.row + 1 === line && n.startPosition.column + 1 === column)[0];
}
