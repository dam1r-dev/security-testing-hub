import { isRequestSource } from "../analyzers/sources";
import { SyntaxNode, findNodes, isFunctionNode } from "../parsers/utils";
import { callArguments } from "./args";
import { FileInfo, FunctionInfo, ProjectContext } from "./project";
import {
  CallTaint,
  Carrier,
  aliasesOfNames,
  containsSourceDirectly,
  expressionCarries,
  getAliases,
  isAllowlistGuarded,
  usesNamesDirectly,
} from "./simple-taint";

/**
 * Taint that comes BACK out of a function through its return value:
 *
 *   function buildQuery(name) { return "SELECT * FROM users WHERE name = '" + name + "'"; }
 *   const q = buildQuery(req.query.name);      // q is attacker-shaped
 *   db.query(q);                                // reported
 *
 *   function getId(req) { return req.params.id; }
 *   db.query("... " + getId(req));              // a call whose result IS request input
 *
 * Same precision rule as everywhere else: a value only counts as carried when it is used DIRECTLY in the returned
 * expression (concatenation, a template literal, the bare name, a ternary). Passing it through another call
 * (`return escape(name)`, `return parseInt(id)`) is a cleaning step we cannot see into, so it contributes nothing;
 * and a function whose own name says it cleans (`sanitize*`, `escape*`, `validate*`, ...) is never followed.
 */

export interface ReturnSummary {
  /** The function returns request input by itself (`return req.params.id`). */
  source: boolean;
  /** Parameters whose value is part of the returned value. */
  params: Set<number>;
}

const EMPTY: ReturnSummary = { source: false, params: new Set() };
const MAX_RETURN_DEPTH = 5;
// A function that says it cleans, validates or converts its input returns a value that is no longer attacker-shaped.
const CLEANING_NAME = /sanitiz|escap|clean|validat|encod|quot|hash|slug|toInt|toNumber|parseInt|parseFloat|numeric|integer|normaliz|whitelist|allowlist|^safe|safe[A-Z]|verif|\bcheck/i;
// `if (!next.startsWith("/")) return fallback;`: the function tests the value before it hands it back.
const CHECK_CALL = /\.(?:includes|has|startsWith|endsWith|test|match|matches|indexOf|every|some)$|^(?:is|has|check|verify|validate|assert|allow)/i;

/** Does `body` test one of `names` (a validator call, or a comparison with something other than null) and bail out? */
function guardsBeforeReturning(body: SyntaxNode, names: Set<string>): boolean {
  for (const statement of findNodes(body, (n) => n.type === "if_statement")) {
    const condition = statement.childForFieldName("condition");
    const consequence = statement.childForFieldName("consequence");
    if (!condition || !consequence || !/\b(?:return|throw)\b/.test(consequence.text)) continue;
    if (findNodes(condition, (n) => n.type === "identifier" && names.has(n.text)).length === 0) continue;
    const validatorCall = findNodes(condition, (n) => n.type === "call_expression").some((call) => CHECK_CALL.test(call.childForFieldName("function")?.text ?? ""));
    const comparison = findNodes(condition, (n) => n.type === "binary_expression").some((cmp) => {
      const op = cmp.childForFieldName("operator")?.text ?? "";
      return /^(?:===?|!==?)$/.test(op) && !/^(?:null|undefined|void 0|""|'')$/.test(cmp.childForFieldName("right")?.text ?? "");
    });
    if (validatorCall || comparison) return true;
  }
  return false;
}

/** Return expressions of `fn` itself (not of functions nested inside it). */
function returnExpressions(fn: FunctionInfo): SyntaxNode[] {
  const body = fn.body;
  if (!body) return [];
  // `(x) => `...${x}``: the body IS the returned expression.
  if (body.type !== "statement_block") return [body];
  const found: SyntaxNode[] = [];
  for (const statement of findNodes(body, (n) => n.type === "return_statement")) {
    let owner: SyntaxNode | null = statement.parent;
    while (owner && !isFunctionNode(owner)) owner = owner.parent;
    if (owner?.id !== fn.node.id) continue;
    const value = statement.namedChild(0);
    if (value) found.push(value);
  }
  return found;
}

/** What the value returned by `fn` is made of (memoised per project). */
export function returnSummary(fn: FunctionInfo, project: ProjectContext, depth = 0): ReturnSummary {
  const key = `${fn.file}|${fn.node.startIndex}`;
  const cached = project.returnSummaries.get(key);
  if (cached) return cached;
  if (project.summarizingReturns.has(key) || depth > MAX_RETURN_DEPTH) return EMPTY;
  if (CLEANING_NAME.test(fn.name) || !fn.body) return EMPTY;

  project.summarizingReturns.add(key);
  const result: ReturnSummary = { source: false, params: new Set() };
  try {
    const returns = returnExpressions(fn);
    if (returns.length > 0) {
      const callTaint = callTaintFor(fn.info, depth + 1);
      const assignments = fn.info.assignmentsIn(fn.body);

      fn.params.forEach((names, index) => {
        if (names.length === 0) return;
        const tainted = aliasesOfNames(names, fn.body as SyntaxNode, callTaint);
        if (guardsBeforeReturning(fn.body as SyntaxNode, tainted)) return;
        if (returns.some((expr) => !isAllowlistGuarded(expr) && expressionCarries(expr, { names: tainted }, callTaint))) result.params.add(index);
      });

      for (const source of findNodes(fn.body, isRequestSource)) {
        const aliases = getAliases(source, fn.body, assignments, callTaint);
        if (guardsBeforeReturning(fn.body, aliases)) continue;
        if (returns.some((expr) => !isAllowlistGuarded(expr) && (containsSourceDirectly(expr, source) || usesNamesDirectly(expr, aliases)))) {
          result.source = true;
          break;
        }
      }
    }
  } finally {
    project.summarizingReturns.delete(key);
  }
  project.returnSummaries.set(key, result);
  return result;
}

/**
 * A `CallTaint` for code in `info`: a call carries the value when the project function it runs returns something built
 * from an argument that carries it.
 */
export function callTaintFor(info: FileInfo, depth = 0): CallTaint {
  let resolved = resolvedCallees.get(info);
  if (!resolved) {
    resolved = new Map();
    resolvedCallees.set(info, resolved);
  }
  const cache = resolved;
  const calleeOf = (call: SyntaxNode): FunctionInfo | null => {
    let found = cache.get(call.id);
    if (found === undefined) {
      found = info.project.resolveCallee(call, info) ?? null;
      cache.set(call.id, found);
    }
    return found;
  };

  const callTaint: CallTaint = (call: SyntaxNode, carrier: Carrier): boolean => {
    if (depth > MAX_RETURN_DEPTH) return false;
    const callee = calleeOf(call);
    if (!callee) return false;
    const summary = returnSummary(callee, info.project, depth);
    if (summary.params.size === 0) return false;
    const args = callArguments(call);
    for (const index of summary.params) {
      const arg = args[index];
      if (arg && expressionCarries(arg, carrier, callTaint)) return true;
    }
    return false;
  };
  return callTaint;
}

const sourceCallCache = new WeakMap<FileInfo, Map<string, SyntaxNode[]>>();
const REQUEST_HOLDER_NAMES = new Set(["req", "request", "ctx", "context", "event", "c"]);
// Every rule, scope and iteration asks about the same calls: resolve each call once per file.
const resolvedCallees = new WeakMap<FileInfo, Map<number, FunctionInfo | null>>();

/**
 * Calls in `scope` that run a project function returning request input by itself (`getId(req)`): they act as
 * sources. Every rule asks about the same scopes, so the answer is shared.
 */
export function sourceReturningCalls(scope: SyntaxNode, info: FileInfo): SyntaxNode[] {
  let perFile = sourceCallCache.get(info);
  if (!perFile) {
    perFile = new Map();
    sourceCallCache.set(info, perFile);
  }
  const key = `${scope.startIndex}:${scope.endIndex}`;
  let found = perFile.get(key);
  if (!found) {
    found = [];
    for (const call of info.callsIn(scope)) {
      if (call.type !== "call_expression") continue;
      // `getId(req)`: a helper that returns request input is handed the request (or its context) to read it from
      if (!(call.childForFieldName("arguments")?.namedChildren ?? []).some((a) => a.type === "identifier" && REQUEST_HOLDER_NAMES.has(a.text))) continue;
      const callee = info.project.resolveCallee(call, info);
      if (callee && returnSummary(callee, info.project).source) found.push(call);
    }
    perFile.set(key, found);
  }
  return found;
}
