import { SyntaxNode } from "../parsers/utils";
import { AnalyzerConfig, BaseAnalyzer } from "./base-analyzer";
import { isRequestSource } from "./sources";

/**
 * Prototype pollution: request data reaches a deep merge, or becomes the KEY of a nested assignment. A body such as
 * `{"__proto__": {"isAdmin": true}}` then adds `isAdmin` to every object in the process, which is how a "set my
 * preferences" endpoint ends up granting admin rights or crashing the server.
 *
 *  - `_.merge(config, req.body)`, `deepmerge(a, req.body)`, `$.extend(true, {}, input)`, `_.set(obj, req.body.path, v)`;
 *  - `target[req.body.a][req.body.b] = value` (two levels of computed keys: the first one can be `__proto__`).
 *
 * `Object.assign` and spread copy one level and cannot pollute (they are the mass-assignment rule's business).
 */

const LODASH = /^(?:_|lodash|lo|ld)\.(?:merge|mergeWith|defaultsDeep|set|setWith|zipObjectDeep)$/;
const OTHER_MERGES = /^(?:merge|deepMerge|deepmerge|deepAssign|mergeDeep|defaultsDeep|extendDeep|assignDeep)$|^(?:\$|jQuery|angular|R|Ramda)\.(?:extend|merge|mergeDeepRight|mergeDeepLeft)$/;

// A bare `merge(...)` is the library's only when the file imports one: many projects write a small `merge` helper of their own.
const MERGE_LIBRARIES = /(?:from\s+|require\(\s*)["'](?:lodash[\w./-]*|deepmerge[\w./-]*|merge-deep|deep-extend|just-extend|defaults-deep|mixin-deep|merge-options|object-path|dot-prop|set-value|extend)["']/;
const importsCache = new WeakMap<object, boolean>();

function importsMergeLibrary(node: SyntaxNode): boolean {
  const tree = node.tree as unknown as object;
  let known = importsCache.get(tree);
  if (known === undefined) {
    known = node.tree.rootNode.namedChildren.some((statement) => (statement.type === "import_statement" || statement.type === "lexical_declaration" || statement.type === "variable_declaration") && MERGE_LIBRARIES.test(statement.text));
    importsCache.set(tree, known);
  }
  return known;
}

function isDeepMerge(node: SyntaxNode): boolean {
  if (node.type !== "call_expression") return false;
  const callee = node.childForFieldName("function")?.text ?? "";
  if (LODASH.test(callee)) return true;
  return OTHER_MERGES.test(callee) && (callee.includes(".") || importsMergeLibrary(node));
}

/** `a[k1][k2] = v` or `a[k1].b = v`: the first computed key decides WHICH object is written to. */
function isNestedKeyedAssignment(node: SyntaxNode): boolean {
  if (node.type !== "assignment_expression") return false;
  const left = node.childForFieldName("left");
  if (!left) return false;
  const outer = left.type === "subscript_expression" || left.type === "member_expression" ? left.childForFieldName("object") : undefined;
  if (!outer) return false;
  const keyedOuter = outer.type === "subscript_expression" && outer.childForFieldName("index")?.type !== "string" && outer.childForFieldName("index")?.type !== "number";
  const keyedLeft = left.type === "subscript_expression" && left.childForFieldName("index")?.type !== "string" && left.childForFieldName("index")?.type !== "number";
  return keyedOuter && (keyedLeft || left.type === "member_expression");
}

function keyExpressions(assignment: SyntaxNode): SyntaxNode[] {
  const left = assignment.childForFieldName("left");
  const keys: SyntaxNode[] = [];
  const index = left?.childForFieldName("index");
  if (index) keys.push(index);
  const outerIndex = left?.childForFieldName("object")?.childForFieldName("index");
  if (outerIndex) keys.push(outerIndex);
  return keys;
}

export class PrototypePollutionAnalyzer extends BaseAnalyzer {
  protected config(): AnalyzerConfig {
    return {
      ruleId: "prototype-pollution",
      severity: "high",
      confidence: "medium",
      isSource: isRequestSource,
      isSink: (node) => isDeepMerge(node) || isNestedKeyedAssignment(node),
      sinkArgs: (sink) => (sink.type === "assignment_expression" ? keyExpressions(sink) : (sink.childForFieldName("arguments")?.namedChildren ?? [])),
      messageFor: (via) =>
        `User-controlled input ('${via}') is merged deeply, or used as the key of a nested assignment. A body like ` +
        `{"__proto__": {"isAdmin": true}} then changes every object in the process (admin flags, crashes, remote code in some stacks). ` +
        `Do not deep-merge request data: pick the fields you accept, or reject the keys __proto__, constructor and prototype, ` +
        `or build the target with Object.create(null) / a Map.`,
    };
  }
}
