import { SyntaxNode, findNodes } from "../parsers/utils";

/**
 * Intra-procedural taint tracking (V3 scope: single function body only).
 *
 * Algorithm (matches the pseudocode in the dev plan):
 *   1. Find source nodes (req.params, req.query, req.body, ...) in the function.
 *   2. Compute which local variables become tainted, following simple
 *      assignment / declaration chains and template-literal interpolation
 *      to a fixpoint (still within the same function body).
 *   3. Find sink nodes (db.query, exec, res.send, ...) and flag any whose
 *      arguments reference a tainted variable, or the source expression directly.
 *
 * This intentionally does NOT follow taint across function calls or files
 * (see plan Phase 2 "NOT FOUND" example) — that's inter-procedural analysis,
 * deferred to v2.
 */

export interface TaintPair {
  source: SyntaxNode;
  sink: SyntaxNode;
  taintedVia: string;
}

const DECLARATOR_TYPES = new Set(["variable_declarator"]);
const ASSIGNMENT_TYPES = new Set(["assignment_expression"]);

function declaredName(node: SyntaxNode): string | undefined {
  if (DECLARATOR_TYPES.has(node.type)) {
    const nameNode = node.childForFieldName("name");
    return nameNode?.type === "identifier" ? nameNode.text : undefined;
  }
  if (ASSIGNMENT_TYPES.has(node.type)) {
    const leftNode = node.childForFieldName("left");
    return leftNode?.type === "identifier" ? leftNode.text : undefined;
  }
  return undefined;
}

function valueNode(node: SyntaxNode): SyntaxNode | undefined {
  if (DECLARATOR_TYPES.has(node.type)) {
    return node.childForFieldName("value") ?? undefined;
  }
  if (ASSIGNMENT_TYPES.has(node.type)) {
    return node.childForFieldName("right") ?? undefined;
  }
  return undefined;
}

function subtreeContainsIdentifier(root: SyntaxNode, name: string): boolean {
  return findNodes(root, (n) => n.type === "identifier" && n.text === name).length > 0;
}

function subtreeContainsNode(root: SyntaxNode, target: SyntaxNode): boolean {
  return root.startIndex <= target.startIndex && root.endIndex >= target.endIndex;
}

/**
 * True if `node` sits inside `boundary` WITHOUT being passed as an argument to
 * some intermediate function call along the way (e.g. template-literal
 * interpolation and string concatenation are "direct"; being wrapped in
 * `sanitize(...)` is not). This is what keeps taint tracking intra-procedural:
 * we don't know what a called function does with its argument, so we don't
 * assume it stays tainted (see plan Phase 2 "NOT FOUND (yet)" example).
 */
function isDirectlyWithin(node: SyntaxNode, boundary: SyntaxNode): boolean {
  let current: SyntaxNode | null = node;
  while (current && current !== boundary) {
    current = current.parent;
    if (!current) return false;
    if (current.type === "arguments") return false;
  }
  return current === boundary;
}

/**
 * Returns the set of local variable names that are tainted by `sourceNode`,
 * by propagating through declarations/assignments in `functionBody` to a fixpoint.
 */
export function getAliases(sourceNode: SyntaxNode, functionBody: SyntaxNode): Set<string> {
  const tainted = new Set<string>();

  const assignmentLikeNodes = findNodes(
    functionBody,
    (n) => DECLARATOR_TYPES.has(n.type) || ASSIGNMENT_TYPES.has(n.type),
  );

  // Seed: the declaration/assignment that directly captures the source expression
  // (not merely passed as an argument to some other function call).
  for (const node of assignmentLikeNodes) {
    const rhs = valueNode(node);
    if (!rhs) continue;
    if (subtreeContainsNode(rhs, sourceNode) && isDirectlyWithin(sourceNode, rhs)) {
      const name = declaredName(node);
      if (name) tainted.add(name);
    }
  }

  // Propagate to a fixpoint: any declaration whose RHS directly references an
  // already-tainted identifier makes its LHS tainted too (covers template
  // literals, concatenation, etc, but not identifiers only reachable through
  // a wrapping function call).
  let changed = true;
  let iterations = 0;
  const MAX_ITERATIONS = 25; // functions are small; this bounds pathological cases
  while (changed && iterations < MAX_ITERATIONS) {
    changed = false;
    iterations += 1;
    for (const node of assignmentLikeNodes) {
      const name = declaredName(node);
      const rhs = valueNode(node);
      if (!name || !rhs || tainted.has(name)) continue;
      for (const taintedName of tainted) {
        const references = findNodes(rhs, (n) => n.type === "identifier" && n.text === taintedName);
        if (references.some((ref) => isDirectlyWithin(ref, rhs))) {
          tainted.add(name);
          changed = true;
          break;
        }
      }
    }
  }

  return tainted;
}

function sinkUsesTaint(sinkCall: SyntaxNode, sourceNode: SyntaxNode, taintedNames: Set<string>): boolean {
  const args = sinkCall.childForFieldName("arguments");
  const scope = args ?? sinkCall;
  if (subtreeContainsNode(scope, sourceNode)) return true;
  for (const name of taintedNames) {
    if (subtreeContainsIdentifier(scope, name)) return true;
  }
  return false;
}

/**
 * Runs intra-procedural source -> sink taint analysis over one function body.
 */
export function analyzeFunctionBody(
  functionBody: SyntaxNode,
  isSource: (node: SyntaxNode) => boolean,
  isSink: (node: SyntaxNode) => boolean,
): TaintPair[] {
  const sources = findNodes(functionBody, isSource);
  const sinks = findNodes(functionBody, isSink);
  if (sources.length === 0 || sinks.length === 0) return [];

  const findings: TaintPair[] = [];

  for (const source of sources) {
    const taintedVars = getAliases(source, functionBody);
    for (const sink of sinks) {
      if (sinkUsesTaint(sink, source, taintedVars)) {
        const via = [...taintedVars][0] ?? source.text.slice(0, 40);
        findings.push({ source, sink, taintedVia: via });
      }
    }
  }

  return findings;
}
