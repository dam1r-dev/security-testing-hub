import { SyntaxNode, findNodes } from "../parsers/utils";

/**
 * Intra-procedural taint tracking: one function body at a time. Following a value
 * into other functions and files is layered on top in interprocedural.ts.
 *
 * Algorithm (matches the pseudocode in the dev plan):
 *   1. Find source nodes (req.params, req.query, req.body, ...) in the function.
 *   2. Compute which local variables become tainted, following simple
 *      assignment / declaration chains and template-literal interpolation
 *      to a fixpoint (still within the same function body).
 *   3. Find sink nodes (db.query, exec, res.send, ...) and flag any whose
 *      arguments reference a tainted variable, or the source expression directly.
 *
 * Taint is not propagated THROUGH a call's arguments (`sanitize(x)`, `parseInt(x)`):
 * we don't know what the callee does with it. Calls into project functions that pass
 * the value to a sink are handled by the summaries in interprocedural.ts.
 */

export interface TaintPair {
  source: SyntaxNode;
  sink: SyntaxNode;
  taintedVia: string;
}

const DECLARATOR_TYPES = new Set(["variable_declarator"]);
const ASSIGNMENT_TYPES = new Set(["assignment_expression"]);

/**
 * Every identifier a pattern binds: `a`, `{ a, b: c = 1, ...rest }`, `[a, b]`.
 * `const { id } = req.params` must taint `id` — destructuring is how most
 * modern handlers read their input.
 */
export function boundNames(pattern: SyntaxNode): string[] {
  switch (pattern.type) {
    case "identifier":
    case "shorthand_property_identifier_pattern":
      return [pattern.text];
    case "object_pattern":
    case "array_pattern":
      return pattern.namedChildren.flatMap(boundNames);
    case "pair_pattern": {
      const value = pattern.childForFieldName("value");
      return value ? boundNames(value) : [];
    }
    case "assignment_pattern":
    case "object_assignment_pattern": {
      const left = pattern.childForFieldName("left");
      return left ? boundNames(left) : [];
    }
    case "rest_pattern": {
      const inner = pattern.namedChild(0);
      return inner ? boundNames(inner) : [];
    }
    default:
      return [];
  }
}

function declaredNames(node: SyntaxNode): string[] {
  if (DECLARATOR_TYPES.has(node.type)) {
    const nameNode = node.childForFieldName("name");
    return nameNode ? boundNames(nameNode) : [];
  }
  if (ASSIGNMENT_TYPES.has(node.type)) {
    const leftNode = node.childForFieldName("left");
    return leftNode?.type === "identifier" ? [leftNode.text] : [];
  }
  return [];
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

// `{ username }` (shorthand) is a use of the variable `username` even though the
// grammar gives it its own node type.
function isIdentifierUse(node: SyntaxNode): boolean {
  return node.type === "identifier" || node.type === "shorthand_property_identifier";
}

function subtreeContainsIdentifier(root: SyntaxNode, name: string): boolean {
  return findNodes(root, (n) => isIdentifierUse(n) && n.text === name).length > 0;
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
export function isDirectlyWithin(node: SyntaxNode, boundary: SyntaxNode): boolean {
  // Compare by id: node-tree-sitter may hand out different wrapper objects for the same node.
  let current: SyntaxNode = node;
  while (current.id !== boundary.id) {
    const parent: SyntaxNode | null = current.parent;
    if (!parent) return false;
    if (parent.type === "arguments" && parent.id !== boundary.id) return false;
    // `table[userKey]` picks WHICH trusted entry is used; the value that comes out is
    // not attacker-written (e.g. `const cfg = providers[name]; fetch(cfg.url)`).
    if (parent.type === "subscript_expression" && parent.childForFieldName("index")?.id === current.id) return false;
    current = parent;
  }
  return true;
}

/**
 * Grows `tainted` to a fixpoint: any declaration/assignment whose right-hand side
 * directly references an already-tainted name makes the names it binds tainted too
 * (template literals and concatenation count; being wrapped in a function call
 * such as `sanitize(x)` or `parseInt(x)` does not).
 */
function propagateTaint(tainted: Set<string>, assignmentLikeNodes: SyntaxNode[]): void {
  let changed = true;
  let iterations = 0;
  const MAX_ITERATIONS = 25; // functions are small; this bounds pathological cases
  while (changed && iterations < MAX_ITERATIONS) {
    changed = false;
    iterations += 1;
    for (const node of assignmentLikeNodes) {
      const names = declaredNames(node);
      const rhs = valueNode(node);
      if (names.length === 0 || !rhs || names.every((name) => tainted.has(name))) continue;
      for (const taintedName of tainted) {
        const references = findNodes(rhs, (n) => isIdentifierUse(n) && n.text === taintedName);
        if (references.some((ref) => isDirectlyWithin(ref, rhs))) {
          for (const name of names) tainted.add(name);
          changed = true;
          break;
        }
      }
    }
  }
}

/** Every declaration / assignment inside `functionBody` (the carriers of aliasing). */
export function assignmentLike(functionBody: SyntaxNode): SyntaxNode[] {
  return findNodes(functionBody, (n) => DECLARATOR_TYPES.has(n.type) || ASSIGNMENT_TYPES.has(n.type));
}

/**
 * Returns the set of local variable names that are tainted by `sourceNode`,
 * by propagating through declarations/assignments in `functionBody` to a fixpoint.
 */
export function getAliases(
  sourceNode: SyntaxNode,
  functionBody: SyntaxNode,
  nodes: SyntaxNode[] = assignmentLike(functionBody),
): Set<string> {
  const tainted = new Set<string>();

  // Seed: the declaration/assignment that directly captures the source expression
  // (not merely passed as an argument to some other function call).
  for (const node of nodes) {
    const rhs = valueNode(node);
    if (!rhs) continue;
    if (subtreeContainsNode(rhs, sourceNode) && isDirectlyWithin(sourceNode, rhs)) {
      for (const name of declaredNames(node)) tainted.add(name);
    }
  }

  propagateTaint(tainted, nodes);
  return tainted;
}

/**
 * Same propagation, but seeded with names instead of a source expression — used
 * for function parameters ("if the caller passes something tainted here, which
 * local names carry it?").
 */
export function aliasesOfNames(seed: Iterable<string>, functionBody: SyntaxNode): Set<string> {
  const tainted = new Set<string>(seed);
  propagateTaint(tainted, assignmentLike(functionBody));
  return tainted;
}

/** True if `expression` directly (not wrapped in a call's arguments) uses any of `names`. */
export function usesNamesDirectly(expression: SyntaxNode, names: Set<string>): boolean {
  if (names.size === 0) return false;
  return findNodes(expression, (n) => isIdentifierUse(n) && names.has(n.text)).some((ref) =>
    isDirectlyWithin(ref, expression),
  );
}

/** True if `source` sits directly inside `expression` (not wrapped in a call's arguments). */
export function containsSourceDirectly(expression: SyntaxNode, source: SyntaxNode): boolean {
  return subtreeContainsNode(expression, source) && isDirectlyWithin(source, expression);
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

export interface TaintHints {
  /** Source nodes already found in this body (the same walk is shared by many rules). */
  sources?: SyntaxNode[];
  /** Declarations/assignments already collected for this body. */
  assignments?: SyntaxNode[];
}

/**
 * Runs intra-procedural source -> sink taint analysis over one function body.
 */
export function analyzeFunctionBody(
  functionBody: SyntaxNode,
  isSource: (node: SyntaxNode) => boolean,
  isSink: (node: SyntaxNode) => boolean,
  hints: TaintHints = {},
): TaintPair[] {
  const sources = hints.sources ?? findNodes(functionBody, isSource);
  if (sources.length === 0) return []; // most functions touch no request data: skip the sink walk
  const sinks = findNodes(functionBody, isSink);
  if (sinks.length === 0) return [];
  const assignments = hints.assignments ?? assignmentLike(functionBody);

  const findings: TaintPair[] = [];

  for (const source of sources) {
    const taintedVars = getAliases(source, functionBody, assignments);
    for (const sink of sinks) {
      if (sinkUsesTaint(sink, source, taintedVars)) {
        const via = [...taintedVars][0] ?? source.text.slice(0, 40);
        findings.push({ source, sink, taintedVia: via });
      }
    }
  }

  return findings;
}
