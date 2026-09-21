import Parser = require("tree-sitter");
import { SourceLocation } from "../types";

export type SyntaxNode = Parser.SyntaxNode;

/** Depth-first walk over every node in the tree, calling `visit` on each. */
export function walk(node: SyntaxNode, visit: (node: SyntaxNode) => void): void {
  visit(node);
  for (const child of node.namedChildren) {
    walk(child, visit);
  }
}

/** Collects every node for which `predicate` returns true. */
export function findNodes(root: SyntaxNode, predicate: (node: SyntaxNode) => boolean): SyntaxNode[] {
  const matches: SyntaxNode[] = [];
  walk(root, (node) => {
    if (predicate(node)) matches.push(node);
  });
  return matches;
}

const FUNCTION_NODE_TYPES = new Set([
  "function_declaration",
  "function_expression",
  "arrow_function",
  "method_definition",
]);

export function isFunctionNode(node: SyntaxNode): boolean {
  return FUNCTION_NODE_TYPES.has(node.type);
}

/** Finds every top-level function-like node in a file (intra-procedural scope unit). */
export function findFunctionBodies(root: SyntaxNode): SyntaxNode[] {
  return findNodes(root, isFunctionNode);
}

/** Walks up from `node` to the nearest enclosing function, or returns undefined at the root. */
export function enclosingFunction(node: SyntaxNode): SyntaxNode | undefined {
  let current: SyntaxNode | null = node.parent;
  while (current) {
    if (isFunctionNode(current)) return current;
    current = current.parent;
  }
  return undefined;
}

export function nodeText(node: SyntaxNode, sourceCode: string): string {
  return sourceCode.slice(node.startIndex, node.endIndex);
}

export function toLocation(node: SyntaxNode, file: string): SourceLocation {
  return {
    file,
    startLine: node.startPosition.row + 1,
    startColumn: node.startPosition.column + 1,
    endLine: node.endPosition.row + 1,
    endColumn: node.endPosition.column + 1,
  };
}

/** True if `node` is (or is inside) a member/call expression whose text matches `pattern`. */
export function matchesCallPattern(node: SyntaxNode, sourceCode: string, pattern: RegExp): boolean {
  if (node.type !== "call_expression") return false;
  const callee = node.firstNamedChild;
  if (!callee) return false;
  return pattern.test(nodeText(callee, sourceCode));
}

/** True if `node` is a member_expression (e.g. req.params, req.query) matching `pattern`. */
export function matchesMemberPattern(node: SyntaxNode, sourceCode: string, pattern: RegExp): boolean {
  if (node.type !== "member_expression" && node.type !== "subscript_expression") return false;
  return pattern.test(nodeText(node, sourceCode));
}

function truncate(text: string, maxLength = 160): string {
  const singleLine = text.replace(/\s+/g, " ").trim();
  return singleLine.length > maxLength ? `${singleLine.slice(0, maxLength)}...` : singleLine;
}

export function snippet(node: SyntaxNode, sourceCode: string): string {
  return truncate(nodeText(node, sourceCode));
}
