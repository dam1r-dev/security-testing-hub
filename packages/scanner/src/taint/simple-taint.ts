import { checkBudget } from "../budget";
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
 * the value to a sink are handled by the summaries in interprocedural.ts, and calls
 * whose RETURN value is built straight from an argument (`const q = build(id)`) by the
 * return summaries in returns.ts, which plug in here as a `CallTaint`.
 */

/** What carries the attacker's value in a function: the source expression itself and/or names it flowed into. */
export interface Carrier {
  source?: SyntaxNode;
  names: Set<string>;
}

/** Does this call EXPRESSION evaluate to something built from the carrier? (return-value taint, see returns.ts) */
export type CallTaint = (call: SyntaxNode, carrier: Carrier) => boolean;

const NO_NAMES: Set<string> = new Set();

export interface TaintPair {
  source: SyntaxNode;
  sink: SyntaxNode;
  taintedVia: string;
}

const DECLARATOR_TYPES = new Set(["variable_declarator"]);
const COMPARISON_OPERATORS = new Set(["==", "===", "!=", "!==", "<", ">", "<=", ">=", "instanceof", "in"]);
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

function subtreeContainsNode(root: SyntaxNode, target: SyntaxNode): boolean {
  return root.startIndex <= target.startIndex && root.endIndex >= target.endIndex;
}

const TRANSFORMING_METHODS = /^(?:map|flatMap|reduce|reduceRight)$/;
const CLEANING_CALL_IN_CALLBACK = /(?:escape\w*|sanitize\w*|encodeURI\w*|parseInt|parseFloat|Number|BigInt|hash\w*|quote\w*)\s*\(/i;

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
    // `items.map((i) => escapeHtml(i)).join("")`: a callback that cleans each element decides what comes out, not the receiver.
    if (parent.type === "member_expression" && parent.childForFieldName("object")?.id === current.id) {
      const call = parent.parent;
      if (call?.type === "call_expression" && call.childForFieldName("function")?.id === parent.id && TRANSFORMING_METHODS.test(parent.childForFieldName("property")?.text ?? "")) {
        const callback = call.childForFieldName("arguments")?.namedChild(0);
        if (callback && (callback.type === "arrow_function" || callback.type === "function_expression") && CLEANING_CALL_IN_CALLBACK.test(callback.text)) return false;
      }
    }
    // `table[userKey]` picks WHICH trusted entry is used; the value that comes out is
    // not attacker-written (e.g. `const cfg = providers[name]; fetch(cfg.url)`).
    if (parent.type === "subscript_expression" && parent.childForFieldName("index")?.id === current.id) return false;
    // What a condition decides is not part of the value: `token ? table[token] : undefined`, `a === b`, `!x`.
    if (parent.type === "ternary_expression" && parent.childForFieldName("condition")?.id === current.id) return false;
    if (parent.type === "binary_expression" && COMPARISON_OPERATORS.has(parent.childForFieldName("operator")?.text ?? "")) return false;
    if (parent.type === "unary_expression" && /^(?:!|typeof|void)$/.test(parent.childForFieldName("operator")?.text ?? "")) return false;
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
function propagateTaint(tainted: Set<string>, assignmentLikeNodes: SyntaxNode[], callTaint?: CallTaint): void {
  let changed = true;
  let iterations = 0;
  const MAX_ITERATIONS = 25; // functions are small; this bounds pathological cases
  while (changed && iterations < MAX_ITERATIONS) {
    changed = false;
    iterations += 1;
    for (const node of assignmentLikeNodes) {
      checkBudget();
      const names = declaredNames(node);
      const rhs = valueNode(node);
      if (names.length === 0 || !rhs || isAllowlistGuarded(rhs) || names.every((name) => tainted.has(name))) continue;
      if (expressionCarries(rhs, { names: tainted }, callTaint)) {
        for (const name of names) tainted.add(name);
        changed = true;
      }
    }
  }
}

/**
 * `const ext = ALLOWED.includes(x) ? x : "jpg"` or `x.startsWith("/") ? x : "/home"`: the value that comes out
 * has been checked, so it is not attacker-controlled any more.
 */
export function isAllowlistGuarded(rhs: SyntaxNode): boolean {
  if (rhs.type !== "ternary_expression") return false;
  return /\.(?:includes|has|startsWith|endsWith|test|match|matches|indexOf)\(/.test(rhs.childForFieldName("condition")?.text ?? "");
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
  callTaint?: CallTaint,
): Set<string> {
  const tainted = new Set<string>();

  // Seed: the declaration/assignment that directly captures the source expression
  // (not merely passed as an argument to some other function call).
  for (const node of nodes) {
    const rhs = valueNode(node);
    if (!rhs || isAllowlistGuarded(rhs)) continue;
    if (expressionCarries(rhs, { source: sourceNode, names: NO_NAMES }, callTaint)) {
      for (const name of declaredNames(node)) tainted.add(name);
    }
  }

  propagateTaint(tainted, nodes, callTaint);
  return tainted;
}

/**
 * Same propagation, but seeded with names instead of a source expression — used
 * for function parameters ("if the caller passes something tainted here, which
 * local names carry it?").
 */
export function aliasesOfNames(seed: Iterable<string>, functionBody: SyntaxNode, callTaint?: CallTaint): Set<string> {
  const tainted = new Set<string>(seed);
  propagateTaint(tainted, assignmentLike(functionBody), callTaint);
  return tainted;
}

/** True if `expression` directly (not wrapped in a call's arguments) uses any of `names`. */
export function usesNamesDirectly(expression: SyntaxNode, names: Set<string>): boolean {
  if (names.size === 0) return false;
  return findNodes(expression, (n) => isIdentifierUse(n) && names.has(n.text)).some((ref) =>
    isDirectlyWithin(ref, expression),
  );
}

/**
 * Does `expression` carry the value: the source itself or a tainted name used directly, or a call to a project
 * function whose return value is built from it (`build(id)`, `"x" + build(id)`)?
 */
export function expressionCarries(expression: SyntaxNode, carrier: Carrier, callTaint?: CallTaint): boolean {
  if (carrier.source && containsSourceDirectly(expression, carrier.source)) return true;
  if (usesNamesDirectly(expression, carrier.names)) return true;
  if (!callTaint) return false;
  return directCalls(expression).some((call) => callTaint(call, carrier));
}

// The calls an expression evaluates to or builds on directly (not inside another call's arguments): one downward walk,
// remembered per tree, because the same expression is asked about again for every source and every iteration.
const directCallCache = new WeakMap<object, Map<number, SyntaxNode[]>>();

function directCalls(expression: SyntaxNode): SyntaxNode[] {
  if (!expression.text.includes("(")) return NO_CALLS;
  const tree = expression.tree as unknown as object;
  let perTree = directCallCache.get(tree);
  if (!perTree) {
    perTree = new Map();
    directCallCache.set(tree, perTree);
  }
  const cached = perTree.get(expression.id);
  if (cached) return cached;

  const calls: SyntaxNode[] = [];
  const visit = (node: SyntaxNode): void => {
    if (node.type === "call_expression") calls.push(node);
    for (const child of node.namedChildren) {
      // the same boundaries as isDirectlyWithin: a value passed as an argument, used as a key, tested by a condition
      // or compared is not part of the value of the expression
      if (node.type === "call_expression" && child.type === "arguments") continue;
      if (node.type === "new_expression" && child.type === "arguments") continue;
      if (node.type === "subscript_expression" && node.childForFieldName("index")?.id === child.id) continue;
      if (node.type === "ternary_expression" && node.childForFieldName("condition")?.id === child.id) continue;
      if (node.type === "binary_expression" && COMPARISON_OPERATORS.has(node.childForFieldName("operator")?.text ?? "")) continue;
      if (node.type === "unary_expression" && /^(?:!|typeof|void)$/.test(node.childForFieldName("operator")?.text ?? "")) continue;
      visit(child);
    }
  };
  visit(expression);
  perTree.set(expression.id, calls);
  return calls;
}

const NO_CALLS: SyntaxNode[] = [];

/** True if `source` sits directly inside `expression` (not wrapped in a call's arguments). */
export function containsSourceDirectly(expression: SyntaxNode, source: SyntaxNode): boolean {
  return subtreeContainsNode(expression, source) && isDirectlyWithin(source, expression);
}

// Calls whose result is no longer attacker-shaped for injection purposes: numeric coercion, hashing,
// escaping/sanitising. (`String(x)` and `x.toString()` are deliberately NOT here: they change nothing.)
const CLEANING_CALLEE =
  /(?:^|\.)(?:parseInt|parseFloat|Number|BigInt|Boolean|hash\w*|\w*Hash|md5|sha\d*|digest|escape\w*|sanitize\w*|safe\w*|validate\w*|verify\w*|encodeURI|encodeURIComponent|quote\w*|isNaN|isFinite)$/i;

/** Does `node` carry the tainted value outside of any cleaning call? */
function carriesTaint(node: SyntaxNode, source: SyntaxNode, names: Set<string>): boolean {
  if (node.startIndex === source.startIndex && node.endIndex === source.endIndex) return true;
  if (isIdentifierUse(node) && names.has(node.text)) return true;
  if (node.type === "call_expression") {
    const callee = node.childForFieldName("function");
    if (callee && CLEANING_CALLEE.test(callee.text)) return false;
  }
  return node.namedChildren.some((child) => carriesTaint(child, source, names));
}

function sinkUsesTaint(
  sinkCall: SyntaxNode,
  sourceNode: SyntaxNode,
  taintedNames: Set<string>,
  sinkArgs?: (sink: SyntaxNode) => SyntaxNode[],
): boolean {
  // Only the arguments that matter for this kind of sink: `db.query(sql, [values])` is dangerous through
  // `sql`, `fs.writeFile(path, data)` through `path`, `redirect(url, { headers })` through `url`.
  const scopes = sinkArgs ? sinkArgs(sinkCall) : [sinkCall.childForFieldName("arguments") ?? sinkCall];
  return scopes.some((scope) => carriesTaint(scope, sourceNode, taintedNames));
}

export interface TaintHints {
  /** Source nodes already found in this body (the same walk is shared by many rules). */
  sources?: SyntaxNode[];
  /** Declarations/assignments already collected for this body. */
  assignments?: SyntaxNode[];
  /** Which arguments of a sink call are dangerous (default: all of them). */
  sinkArgs?: (sink: SyntaxNode) => SyntaxNode[];
  /** Request data that arrives as destructured handler parameters (`({ body }: Request, res) => ...`). */
  origins?: Array<{ node: SyntaxNode; names: string[] }>;
  /** Follows a value through project functions that return something built from their argument. */
  callTaint?: CallTaint;
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
  const origins = hints.origins ?? [];
  if (sources.length === 0 && origins.length === 0) return []; // most functions touch no request data: skip the sink walk
  const sinks = findNodes(functionBody, isSink);
  if (sinks.length === 0) return [];
  const assignments = hints.assignments ?? assignmentLike(functionBody);

  const findings: TaintPair[] = [];

  for (const source of sources) {
    const taintedVars = getAliases(source, functionBody, assignments, hints.callTaint);
    for (const sink of sinks) {
      if (sinkUsesTaint(sink, source, taintedVars, hints.sinkArgs)) {
        const via = [...taintedVars][0] ?? source.text.slice(0, 40);
        findings.push({ source, sink, taintedVia: via });
      }
    }
  }

  for (const origin of origins) {
    const taintedVars = aliasesOfNames(origin.names, functionBody, hints.callTaint);
    for (const sink of sinks) {
      if (sinkUsesTaint(sink, origin.node, taintedVars, hints.sinkArgs)) {
        findings.push({ source: origin.node, sink, taintedVia: origin.names[0] ?? "request" });
      }
    }
  }

  return findings;
}
