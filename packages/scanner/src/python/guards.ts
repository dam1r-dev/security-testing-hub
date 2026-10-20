import { SyntaxNode } from "../parsers/utils";

/**
 * A value that has been CHECKED is not the caller's text any more: `if x.isdigit():`, `if mode in ALLOWED:`, `if re.fullmatch(r"\d+", x):`,
 * `if not is_valid(x): abort(400)`. The engine takes the checked names out of the tainted set inside the branch the check guards, and after
 * an `if` that ends in `return` / `raise` / `abort()` when the check failed.
 *
 * Only plain names are tracked (the usual shape), and only checks that say what the value IS: a method such as `isdigit`, membership in a
 * collection, equality with a literal, a full-match pattern, `isinstance(x, int)`, or a function named like a validator.
 */

export interface Guard {
  /** Names that are checked when the condition is true. */
  yes: string[];
  /** Names that are checked when the condition is false. */
  no: string[];
}

const NONE: Guard = { yes: [], no: [] };
const CHECK_METHOD = new Set(["isdigit", "isnumeric", "isdecimal", "isalnum", "isalpha", "isidentifier", "isascii"]);
const VALIDATOR_NAME = /^(?:is_valid\w*|valid_\w+|validate\w*|is_safe\w*|is_allowed\w*|allowed\w*|check_\w+|is_numeric|is_int|is_uuid|is_slug|is_email\w*|isvalid\w*)$/i;

function identifiers(node: SyntaxNode | null | undefined): string[] {
  if (!node) return [];
  if (node.type === "identifier") return [node.text];
  if (node.type === "argument_list" || node.type === "parenthesized_expression") return node.namedChildren.flatMap(identifiers);
  return [];
}

function union(a: string[], b: string[]): string[] {
  return [...new Set([...a, ...b])];
}

export function conditionGuard(condition: SyntaxNode | null | undefined): Guard {
  if (!condition) return NONE;
  switch (condition.type) {
    case "parenthesized_expression":
      return conditionGuard(condition.namedChild(0));
    case "not_operator": {
      const inner = conditionGuard(condition.namedChild(0));
      return { yes: inner.no, no: inner.yes };
    }
    case "boolean_operator": {
      const left = conditionGuard(condition.childForFieldName("left"));
      const right = conditionGuard(condition.childForFieldName("right"));
      const operator = condition.childForFieldName("operator")?.text ?? "";
      // a and b: both held when it is true; a or b: both failed when it is false
      return operator === "and" ? { yes: union(left.yes, right.yes), no: [] } : { yes: [], no: union(left.no, right.no) };
    }
    case "comparison_operator": {
      const [left, right] = condition.namedChildren;
      if (left?.type !== "identifier" || !right) return NONE;
      const text = condition.text.slice(left.text.length).trimStart();
      const known = right.type === "string" || right.type === "integer" || right.type === "identifier" || right.type === "attribute" || right.type === "list" || right.type === "tuple" || right.type === "set";
      if (!known) return NONE;
      if (/^(?:in|==|is)\s/.test(text) && !/^is\s+not\b/.test(text)) return { yes: [left.text], no: [] };
      if (/^(?:not\s+in|!=|is\s+not)\s/.test(text)) return { yes: [], no: [left.text] };
      return NONE;
    }
    case "call": {
      const callee = condition.childForFieldName("function");
      const args = condition.childForFieldName("arguments");
      if (!callee) return NONE;
      if (callee.type === "attribute") {
        const method = callee.childForFieldName("attribute")?.text ?? "";
        const object = callee.childForFieldName("object");
        if (CHECK_METHOD.has(method) && object?.type === "identifier") return { yes: [object.text], no: [] };
        // pattern.fullmatch(x)
        if (method === "fullmatch") return { yes: identifiers(args), no: [] };
      }
      const name = callee.text;
      if (/^re\.fullmatch$/.test(name)) return { yes: identifiers(args?.namedChild(1)), no: [] };
      if (name === "re.match" || name === "re.search") {
        // anchored at both ends, or it only says that a part of the value looks right
        const pattern = args?.namedChild(0)?.text ?? "";
        return /["']\^|["']\\A/.test(pattern) && /(?:\$|\\Z)["']/.test(pattern) ? { yes: identifiers(args?.namedChild(1)), no: [] } : NONE;
      }
      if (name === "isinstance") return { yes: identifiers(args?.namedChild(0)), no: [] };
      if (VALIDATOR_NAME.test(name.split(".").pop() ?? "")) return { yes: identifiers(args), no: [] };
      return NONE;
    }
    default:
      return NONE;
  }
}

const EXITING_CALL = /^(?:abort|sys\.exit|exit|quit|os\._exit|HttpResponseBadRequest|HttpResponseForbidden|HttpResponseNotAllowed|Http404|PermissionDenied)$/;

/** Does this branch always leave the function (or the loop) at its last statement? */
export function alwaysExits(block: SyntaxNode | null | undefined): boolean {
  if (!block) return false;
  const statements = block.namedChildren.filter((c) => c.type !== "comment");
  const last = statements[statements.length - 1];
  if (!last) return false;
  if (last.type === "return_statement" || last.type === "raise_statement" || last.type === "continue_statement" || last.type === "break_statement") return true;
  if (last.type === "expression_statement") {
    const call = last.namedChild(0);
    if (call?.type === "call") return EXITING_CALL.test(call.childForFieldName("function")?.text ?? "");
  }
  return false;
}
