import Parser = require("tree-sitter");
import { checkBudget } from "../budget";
import { SourceLocation } from "../types";

export type SyntaxNode = Parser.SyntaxNode;

/**
 * Depth-first (pre-order) walk over every node in the tree, calling `visit` on each. Iterative on purpose: a file with
 * a 200 000-term `1+1+1+...` has a 200 000-deep tree, and recursion would overflow the stack. Also the place where the
 * per-file time budget is checked (see budget.ts).
 */
export function walk(node: SyntaxNode, visit: (node: SyntaxNode) => void): void {
  const stack: SyntaxNode[] = [node];
  while (stack.length > 0) {
    const current = stack.pop() as SyntaxNode;
    checkBudget();
    visit(current);
    const children = current.namedChildren;
    for (let i = children.length - 1; i >= 0; i--) stack.push(children[i] as SyntaxNode);
  }
}

/**
 * Every node of a whole tree in pre-order, kept for as long as the tree lives. About sixty `findNodes(rootNode, ...)` calls run on each file
 * (every analyzer looks for its own kind of node), and each one used to walk the tree again through the native binding, where reading
 * `namedChildren` builds a new JavaScript object per node: that walk was most of the time a big file took. The list is built once per tree.
 */
// Only the last few trees: a project keeps hundreds of parsed trees for cross-file lookups, and a node list per tree held them all in memory
// (a 1 000-file PHP project went from 19 s to 30 s in garbage collection). The file being analysed is queried again and again; the others are not.
const KEPT_TREES = 3;
const wholeTrees: Array<{ tree: object; rootId: number; nodes: SyntaxNode[] }> = [];

function nodesOfWholeTree(root: SyntaxNode): SyntaxNode[] | undefined {
  const tree = (root as unknown as { tree?: object }).tree;
  if (!tree) return undefined;
  const index = wholeTrees.findIndex((entry) => entry.tree === tree);
  if (index >= 0) {
    const entry = wholeTrees[index] as (typeof wholeTrees)[number];
    if (entry.rootId !== root.id) return undefined; // a query over part of the tree walks that part
    if (index > 0) {
      wholeTrees.splice(index, 1);
      wholeTrees.unshift(entry);
    }
    return entry.nodes;
  }
  if (root.parent) return undefined;
  const nodes: SyntaxNode[] = [];
  walk(root, (node) => {
    nodes.push(node);
  });
  wholeTrees.unshift({ tree, rootId: root.id, nodes });
  if (wholeTrees.length > KEPT_TREES) wholeTrees.length = KEPT_TREES;
  return nodes;
}

/** Collects every node for which `predicate` returns true. */
export function findNodes(root: SyntaxNode, predicate: (node: SyntaxNode) => boolean): SyntaxNode[] {
  const matches: SyntaxNode[] = [];
  const all = nodesOfWholeTree(root);
  if (all) {
    for (let i = 0; i < all.length; i++) {
      checkBudget();
      const node = all[i] as SyntaxNode;
      if (predicate(node)) matches.push(node);
    }
    return matches;
  }
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

/**
 * The code of a node without its comments. A hint such as `req.session` that only appears in a comment (a commented-out fix, an
 * explanation of the bug) is not a check; matching raw text counted it as one.
 */
export function withoutComments(text: string): string {
  return text.replace(/\/\*[\s\S]*?\*\//g, " ").replace(/(^|[^:])\/\/.*$/gm, "$1");
}
