import { SyntaxNode, findNodes } from "../parsers/utils";
import { FileInfo, FunctionInfo, ProjectContext } from "./project";
import { aliasesOfNames, containsSourceDirectly, getAliases, usesNamesDirectly } from "./simple-taint";

/**
 * Cross-function (and cross-file) taint.
 *
 * Per function and per rule we compute a *summary*: which parameters flow into a
 * dangerous call somewhere inside it (directly, or through further calls). At a
 * call site that passes user input into such a parameter we then report the flow
 * — at the call site, where the user input is visible.
 *
 *   routes/users.js     userService.findByName(req.query.name)      <- reported here
 *   services/users.js   findByName(name) { return db.query("... " + name) }
 *
 * Deliberately NOT modelled: taint coming back through return values, callbacks,
 * and objects stored in fields. Each of those would need to tell "returns something
 * derived from the input" apart from "returns a sanitised value", which a
 * name-based analysis can't, so we under-report rather than guess.
 */

export interface SinkSpec {
  ruleId: string;
  isSink: (node: SyntaxNode) => boolean;
  /** The arguments of a sink call that must not be attacker-controlled (default: all). */
  sinkArgs?: (sink: SyntaxNode) => SyntaxNode[];
}

export interface SinkTrace {
  file: string;
  line: number;
  /** Function names from the callee down to the one that makes the dangerous call. */
  path: string[];
}

export interface CrossFileFlow {
  source: SyntaxNode;
  call: SyntaxNode;
  calleeName: string;
  trace: SinkTrace;
  /** The local name (or source text) the value travels under in the caller. */
  via: string;
}

const MAX_CALL_DEPTH = 6;
const NO_SINKS: Map<number, SinkTrace> = new Map();

/** Positional arguments of a call / `new`; stops at the first spread, after which positions are unknown. */
export function callArguments(call: SyntaxNode): SyntaxNode[] {
  const args = call.childForFieldName("arguments");
  if (!args) return [];
  const result: SyntaxNode[] = [];
  for (const arg of args.namedChildren) {
    if (arg.type === "comment") continue;
    if (arg.type === "spread_element") break;
    result.push(arg);
  }
  return result;
}

export function firstArgument(call: SyntaxNode): SyntaxNode[] {
  const first = callArguments(call)[0];
  return first ? [first] : [];
}

function isCall(node: SyntaxNode): boolean {
  return node.type === "call_expression" || node.type === "new_expression";
}

/** Which parameters of `fn` reach a dangerous call for this rule? (memoised per project) */
export function sinkParams(fn: FunctionInfo, spec: SinkSpec, project: ProjectContext, depth = 0): Map<number, SinkTrace> {
  const key = `${spec.ruleId}|${fn.file}|${fn.node.startIndex}`;
  const cached = project.summaries.get(key) as Map<number, SinkTrace> | undefined;
  if (cached) return cached;
  // A cycle (recursion) or a too-deep chain contributes nothing rather than guessing.
  if (project.summarizing.has(key) || depth > MAX_CALL_DEPTH) return NO_SINKS;
  const body = fn.body;
  if (!body || fn.params.length === 0) return NO_SINKS;

  project.summarizing.add(key);
  const result = new Map<number, SinkTrace>();
  try {
    const sinks = findNodes(body, spec.isSink);
    const calls = findNodes(body, (n) => isCall(n) && !spec.isSink(n));

    fn.params.forEach((names, index) => {
      if (names.length === 0) return;
      const tainted = aliasesOfNames(names, body);

      for (const sink of sinks) {
        const args = spec.sinkArgs ? spec.sinkArgs(sink) : callArguments(sink);
        if (args.some((arg) => usesNamesDirectly(arg, tainted))) {
          result.set(index, { file: fn.file, line: sink.startPosition.row + 1, path: [fn.name] });
          return;
        }
      }

      for (const call of calls) {
        const args = callArguments(call);
        if (!args.some((arg) => usesNamesDirectly(arg, tainted))) continue;
        const callee = project.resolveCallee(call, fn.info);
        if (!callee) continue;
        for (const [calleeIndex, trace] of sinkParams(callee, spec, project, depth + 1)) {
          const arg = args[calleeIndex];
          if (arg && usesNamesDirectly(arg, tainted)) {
            result.set(index, { ...trace, path: [fn.name, ...trace.path] });
            return;
          }
        }
      }
    });
  } finally {
    project.summarizing.delete(key);
  }
  project.summaries.set(key, result);
  return result;
}

/**
 * Calls inside `scope` that hand user input to a project function whose parameter
 * reaches a dangerous call. `sources` are the rule's own user-input nodes in `scope`.
 */
export function findCrossFileFlows(
  scope: SyntaxNode,
  spec: SinkSpec,
  sources: SyntaxNode[],
  info: FileInfo,
  origins: Array<{ node: SyntaxNode; names: string[] }> = [],
): CrossFileFlow[] {
  if (sources.length === 0 && origins.length === 0) return [];
  const assignments = info.assignmentsIn(scope);
  const tracked = [
    ...sources.map((source) => ({ source, names: getAliases(source, scope, assignments) })),
    ...origins.map((origin) => ({ source: origin.node, names: aliasesOfNames(origin.names, scope) })),
  ];

  const flows: CrossFileFlow[] = [];
  for (const call of info.callsIn(scope)) {
    if (spec.isSink(call)) continue;
    const args = callArguments(call);
    if (args.length === 0) continue;

    // Which argument positions carry user input, and from which source?
    const carriers = new Map<number, { source: SyntaxNode; via: string }>();
    args.forEach((arg, index) => {
      for (const { source, names } of tracked) {
        if (containsSourceDirectly(arg, source)) {
          carriers.set(index, { source, via: source.text.slice(0, 40) });
          return;
        }
        if (usesNamesDirectly(arg, names)) {
          carriers.set(index, { source, via: [...names][0] ?? source.text.slice(0, 40) });
          return;
        }
      }
    });
    if (carriers.size === 0) continue;

    const callee = info.project.resolveCallee(call, info);
    if (!callee) continue;
    const summary = sinkParams(callee, spec, info.project);
    for (const [index, carrier] of carriers) {
      const trace = summary.get(index);
      if (trace) {
        flows.push({ source: carrier.source, call, calleeName: callee.name, trace, via: carrier.via });
        break; // one finding per call
      }
    }
  }
  return flows;
}
