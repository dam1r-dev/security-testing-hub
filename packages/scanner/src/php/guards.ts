import { SyntaxNode } from "../parsers/utils";

/**
 * A value that has been CHECKED is not the caller's text any more: `if (is_numeric($id)) { ... }`, `if (in_array($page, $allowed)) { ... }`,
 * `if (!preg_match('/^\d+$/', $x)) { exit; }`. The engine takes the checked variables out of the tainted set inside the branch the check
 * guards, and after an `if` that ends in `return` / `exit` / `throw` when the check failed. See python/guards.ts for the same idea.
 */

export interface Guard {
  yes: string[];
  no: string[];
}

const NONE: Guard = { yes: [], no: [] };
const VALIDATOR_FUNCTION = /^(?:is_numeric|is_int|is_integer|is_float|is_bool|ctype_digit|ctype_alnum|ctype_alpha|ctype_xdigit|ctype_upper|ctype_lower|is_valid\w*|validate\w*|is_safe\w*|is_allowed\w*|allowed\w*|check_\w+)$/i;

function variableOf(node: SyntaxNode | null | undefined): string[] {
  if (!node) return [];
  if (node.type === "variable_name") return [node.text];
  if (node.type === "argument") return variableOf(node.namedChild(node.namedChildCount - 1));
  // is_numeric($parts[0]): the check names one element; the usual shape is a list of values that are all checked (an IP address split at the dots)
  if (node.type === "subscript_expression") return variableOf(node.namedChild(0));
  return [];
}

function union(a: string[], b: string[]): string[] {
  return [...new Set([...a, ...b])];
}

function argumentsList(call: SyntaxNode): SyntaxNode[] {
  return (call.childForFieldName("arguments")?.namedChildren ?? []).map((a) => (a.type === "argument" ? (a.namedChild(a.namedChildCount - 1) as SyntaxNode) : a));
}

export function conditionGuard(condition: SyntaxNode | null | undefined): Guard {
  if (!condition) return NONE;
  switch (condition.type) {
    case "parenthesized_expression":
      return conditionGuard(condition.namedChild(0));
    case "unary_op_expression": {
      if (condition.text.trimStart().startsWith("!")) {
        const inner = conditionGuard(condition.namedChild(condition.namedChildCount - 1));
        return { yes: inner.no, no: inner.yes };
      }
      return NONE;
    }
    case "binary_expression": {
      const operator = condition.childForFieldName("operator")?.text ?? "";
      const left = conditionGuard(condition.childForFieldName("left"));
      const right = conditionGuard(condition.childForFieldName("right"));
      if (operator === "&&" || operator.toLowerCase() === "and") return { yes: union(left.yes, right.yes), no: [] };
      if (operator === "||" || operator.toLowerCase() === "or") return { yes: [], no: union(left.no, right.no) };
      // $x === 'literal' / $x == 5: the value is known when it holds
      if (/^(?:===?)$/.test(operator)) {
        const l = condition.childForFieldName("left");
        const r = condition.childForFieldName("right");
        const literal = (n: SyntaxNode | null): boolean => !!n && (n.type === "string" || n.type === "integer" || n.type === "float" || n.type === "boolean" || n.type === "name" || n.type === "class_constant_access_expression");
        if (l?.type === "variable_name" && literal(r)) return { yes: [l.text], no: [] };
      }
      if (/^(?:!==?)$/.test(operator)) {
        const l = condition.childForFieldName("left");
        const r = condition.childForFieldName("right");
        if (l?.type === "variable_name" && r && (r.type === "string" || r.type === "integer")) return { yes: [], no: [l.text] };
      }
      return NONE;
    }
    case "function_call_expression": {
      const name = (condition.childForFieldName("function")?.text ?? "").replace(/^\\/, "");
      const args = argumentsList(condition);
      const lower = name.toLowerCase();
      if (VALIDATOR_FUNCTION.test(name)) return { yes: args.flatMap((a) => variableOf(a)), no: [] };
      if (lower === "in_array") return { yes: variableOf(args[0]), no: [] };
      if (lower === "filter_var") return /FILTER_VALIDATE_/.test(args[1]?.text ?? "") ? { yes: variableOf(args[0]), no: [] } : NONE;
      if (lower === "preg_match") {
        // anchored at both ends: the whole value fits the pattern
        const pattern = args[0]?.text ?? "";
        return /^["']\W?\^/.test(pattern) && /(?:\$|\\z|\\Z)\W?[a-z]*["']$/.test(pattern) ? { yes: variableOf(args[1]), no: [] } : NONE;
      }
      return NONE;
    }
    default:
      return NONE;
  }
}

/** Does this branch always leave (return, exit, throw, die) at its last statement? */
export function alwaysExits(block: SyntaxNode | null | undefined): boolean {
  if (!block) return false;
  const statements = block.namedChildren.filter((c) => c.type !== "comment");
  const last = statements[statements.length - 1];
  if (!last) return false;
  if (last.type === "return_statement" || last.type === "exit_statement" || last.type === "continue_statement" || last.type === "break_statement" || last.type === "throw_expression") return true;
  if (last.type === "expression_statement") {
    const inner = last.namedChild(0);
    if (inner?.type === "throw_expression") return true;
    if (inner?.type === "function_call_expression") return /^(?:die|exit|abort|wp_die)$/i.test(inner.childForFieldName("function")?.text ?? "");
  }
  return false;
}
