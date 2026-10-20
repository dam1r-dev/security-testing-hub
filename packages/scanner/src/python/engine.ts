import { checkBudget } from "../budget";
import { SyntaxNode } from "../parsers/utils";
import { alwaysExits, conditionGuard } from "./guards";

/**
 * Taint tracking for Python (Flask, FastAPI, Django). One function at a time, in the order the statements run:
 *
 *   q = request.args.get("q")          # q is the caller's
 *   sql = f"SELECT ... '{q}'"          # so is sql
 *   cur.execute(sql)                   # a sink that is handed it
 *
 * What carries the value on: f-strings, `+`, `%`, `.format()`, `.join()`, `.strip()`-style methods, subscripts and attributes of a
 * tainted object, `str()` and friends. What stops it: a call that cleans (`int()`, `escape()`, `quote()`, `secure_filename()`...), and a
 * reassignment to something clean. Any other call is not followed (the same rule as the JavaScript engine: an unknown function may do
 * anything with its argument). Walks are iterative: a hostile file with a 60 000-deep expression must not overflow the stack.
 */

export interface Origin {
  name: string;
  /** Why this name is the caller's: "route parameter", "request.args". Shown in messages. */
  why: string;
}

// `request.args`, `request.form["x"]`, `self.request.GET.get("x")`, `request.query_params`, `request.json`...
const REQUEST_ATTRIBUTE =
  /^(?:self\.)?request\.(?:args|form|values|json|data|cookies|headers|files|environ|view_args|GET|POST|COOKIES|META|FILES|body|query_params|path_params|query|params|stream)\b/;
// `request.get_json()`, `await request.json()`, `request.get_data()`, `await request.form()`
const REQUEST_CALL = /^(?:self\.)?request\.(?:get_json|get_data|json|form|body|stream|data)$/;

const CLEANING_FUNCTION =
  /^(?:int|float|bool|len|round|abs|ord|chr|hash|id|uuid\.UUID|UUID|Decimal|decimal\.Decimal|datetime\.\w+|escape|html\.escape|markupsafe\.escape|xml\.sax\.saxutils\.escape|quote|quote_plus|urllib\.parse\.quote(?:_plus)?|shlex\.quote|secure_filename|werkzeug\.utils\.secure_filename|os\.path\.basename|basename|slugify|bleach\.clean|sanitize\w*|validate\w*|verify\w*|safe\w*|isinstance|re\.escape|hashlib\.\w+|generate_password_hash|check_password_hash|md5|sha\d+|bcrypt\.\w+|url_for|reverse|reverse_lazy|get_object_or_404)$/;
// Calls that give back (a form of) their argument: the value is still the caller's.
const PASS_THROUGH_FUNCTION =
  /^(?:str|bytes|bytearray|repr|ascii|list|tuple|set|frozenset|dict|sorted|reversed|min|max|text|sa\.text|sqlalchemy\.text|RawSQL|os\.path\.join|os\.path\.normpath|os\.path\.abspath|posixpath\.join|Path|PurePath|pathlib\.Path|format|unquote|urllib\.parse\.unquote|html\.unescape|base64\.b64decode|json\.loads|loads)$/;
// Methods of a tainted receiver that give back text built from it.
const PROPAGATING_METHOD = new Set([
  "strip", "lstrip", "rstrip", "lower", "upper", "title", "capitalize", "casefold", "swapcase", "split", "rsplit", "splitlines", "partition",
  "rpartition", "replace", "format", "format_map", "join", "encode", "decode", "get", "getlist", "pop", "popitem", "items", "values", "keys",
  "copy", "read", "readline", "readlines", "to_dict", "setdefault", "zfill", "ljust", "rjust", "center", "expandtabs", "removeprefix",
  "removesuffix", "text", "json", "getvalue", "__getitem__", "first", "last",
]);
// ...and these also put their ARGUMENTS into the result.
const BUILDING_METHOD = new Set(["format", "format_map", "join", "replace", "ljust", "rjust", "center", "zfill", "removeprefix", "removesuffix"]);

export function isRequestSource(node: SyntaxNode): boolean {
  if (node.type === "attribute" || node.type === "subscript") return REQUEST_ATTRIBUTE.test(node.text);
  if (node.type === "call") {
    const callee = node.childForFieldName("function");
    return !!callee && (REQUEST_CALL.test(callee.text) || (callee.type === "attribute" && REQUEST_ATTRIBUTE.test(callee.text) && PROPAGATING_METHOD.has(callee.childForFieldName("attribute")?.text ?? "")));
  }
  return false;
}

export function calleeText(call: SyntaxNode): string {
  return call.childForFieldName("function")?.text ?? "";
}

/** The positional arguments of a call, and its keyword arguments by name. */
export function callArguments(call: SyntaxNode): { positional: SyntaxNode[]; keywords: Map<string, SyntaxNode> } {
  const positional: SyntaxNode[] = [];
  const keywords = new Map<string, SyntaxNode>();
  for (const arg of call.childForFieldName("arguments")?.namedChildren ?? []) {
    if (arg.type === "comment") continue;
    if (arg.type === "keyword_argument") {
      const name = arg.childForFieldName("name")?.text;
      const value = arg.childForFieldName("value");
      if (name && value) keywords.set(name, value);
    } else {
      positional.push(arg);
    }
  }
  return { positional, keywords };
}

/** Names a pattern binds: `a`, `a, b`, `(a, b)`, `[a, *rest]`. */
export function boundNames(pattern: SyntaxNode): string[] {
  switch (pattern.type) {
    case "identifier":
      return [pattern.text];
    case "pattern_list":
    case "tuple_pattern":
    case "list_pattern":
    case "tuple":
    case "list":
      return pattern.namedChildren.flatMap(boundNames);
    case "list_splat_pattern":
    case "list_splat":
      return pattern.namedChildren.flatMap(boundNames);
    default:
      return [];
  }
}

/**
 * Which part of `expression` carries a tainted value, as text (a name or a request expression), or undefined when none does.
 * `tainted` is the set of names that are the caller's right now.
 */
export function carriedBy(expression: SyntaxNode, tainted: ReadonlySet<string>): string | undefined {
  const stack: SyntaxNode[] = [expression];
  while (stack.length > 0) {
    const node = stack.pop() as SyntaxNode;
    checkBudget();
    switch (node.type) {
      case "identifier":
        if (tainted.has(node.text)) return node.text;
        break;
      case "attribute":
      case "subscript": {
        if (isRequestSource(node)) return node.text;
        const base = node.childForFieldName("object") ?? node.childForFieldName("value");
        if (base) stack.push(base);
        break;
      }
      case "call": {
        if (isRequestSource(node)) return node.text.length > 60 ? `${node.text.slice(0, 57)}...` : node.text;
        const callee = node.childForFieldName("function");
        if (!callee) break;
        const name = callee.text;
        if (CLEANING_FUNCTION.test(name)) break;
        const args = node.childForFieldName("arguments")?.namedChildren ?? [];
        if (callee.type === "attribute") {
          const method = callee.childForFieldName("attribute")?.text ?? "";
          const receiver = callee.childForFieldName("object");
          if (PROPAGATING_METHOD.has(method) && receiver) {
            stack.push(receiver);
            if (BUILDING_METHOD.has(method)) for (const a of args) stack.push(a.type === "keyword_argument" ? (a.childForFieldName("value") ?? a) : a);
          } else if (PASS_THROUGH_FUNCTION.test(name)) {
            for (const a of args) stack.push(a.type === "keyword_argument" ? (a.childForFieldName("value") ?? a) : a);
          }
        } else if (PASS_THROUGH_FUNCTION.test(name)) {
          for (const a of args) stack.push(a.type === "keyword_argument" ? (a.childForFieldName("value") ?? a) : a);
        }
        break;
      }
      case "string":
        // f"...{value}...": only the interpolations hold anything of the caller's
        for (const part of node.namedChildren) if (part.type === "interpolation") stack.push(part);
        break;
      case "interpolation":
        for (const part of node.namedChildren) stack.push(part);
        break;
      case "conditional_expression": {
        // `a if condition else b`: the value is a or b (children: a, condition, b)
        const parts = node.namedChildren;
        if (parts[0]) stack.push(parts[0]);
        if (parts[2]) stack.push(parts[2]);
        break;
      }
      case "binary_operator":
      case "boolean_operator":
      case "parenthesized_expression":
      case "await":
      case "list":
      case "tuple":
      case "set":
      case "dictionary":
      case "pair":
      case "list_splat":
      case "dictionary_splat":
      case "list_comprehension":
      case "set_comprehension":
      case "generator_expression":
      case "dictionary_comprehension":
      case "concatenated_string":
      case "expression_list":
        for (const child of node.namedChildren) stack.push(child);
        break;
      default:
        break;
    }
  }
  return undefined;
}

/** Walks a function's own statements (not the functions and classes defined inside it), reporting events in the order they happen. */
export interface WalkHandlers {
  /** Before the children of a node: used for loops, whose variable is tainted by what they iterate over. */
  enter?(node: SyntaxNode): void;
  /** After the children: assignments take effect, calls are checked, `return` values are looked at. */
  exit?(node: SyntaxNode): void;
}

export function walkFunction(fn: SyntaxNode, handlers: WalkHandlers): void {
  const body = fn.childForFieldName("body");
  if (!body) return;
  const stack: Array<{ node: SyntaxNode; leaving: boolean }> = [{ node: body, leaving: false }];
  while (stack.length > 0) {
    const { node, leaving } = stack.pop() as { node: SyntaxNode; leaving: boolean };
    checkBudget();
    if (leaving) {
      handlers.exit?.(node);
      continue;
    }
    if (node.type === "function_definition" || node.type === "class_definition" || node.type === "lambda") continue; // its own scope
    handlers.enter?.(node);
    stack.push({ node, leaving: true });
    const children = node.namedChildren;
    for (let i = children.length - 1; i >= 0; i--) stack.push({ node: children[i] as SyntaxNode, leaving: false });
  }
}

/**
 * Runs `onCall` for every call and `onReturn` for every `return` of the function, with the names that are the caller's AT THAT POINT
 * (assignments and loops update the set as the walk goes; a name assigned something clean is no longer tainted).
 */
export function trackTaint(
  fn: SyntaxNode,
  origins: ReadonlySet<string>,
  handlers: { onCall?(call: SyntaxNode, tainted: ReadonlySet<string>): void; onReturn?(statement: SyntaxNode, tainted: ReadonlySet<string>): void },
): void {
  const tainted = new Set(origins);
  const assign = (targets: SyntaxNode | null, value: SyntaxNode | null, additive: boolean): void => {
    if (!targets || !value) return;
    const names = boundNames(targets);
    if (names.length === 0) return;
    const carries = carriedBy(value, tainted) !== undefined;
    for (const name of names) {
      if (carries) tainted.add(name);
      else if (!additive) tainted.delete(name); // `x = int(x)`: no longer the caller's text
    }
  };
  // Names a check has cleared inside one branch, put back when the branch ends: block node id -> the names taken out.
  const branchGuards = new Map<number, string[]>();
  const taken = new Map<number, string[]>();
  walkFunction(fn, {
    enter(node) {
      if (node.type === "if_statement" || node.type === "elif_clause") {
        const guard = conditionGuard(node.childForFieldName("condition"));
        const consequence = node.childForFieldName("consequence");
        if (consequence && guard.yes.length > 0) branchGuards.set(consequence.id, guard.yes);
        // the else branch of an if/elif chain: what the first check settles when it fails
        if (node.type === "if_statement" && guard.no.length > 0) {
          for (const clause of node.namedChildren) if (clause.type === "else_clause") branchGuards.set(clause.id, guard.no);
        }
      }
      const cleared = branchGuards.get(node.id);
      if (cleared) {
        const names = cleared.filter((name) => tainted.has(name));
        for (const name of names) tainted.delete(name);
        taken.set(node.id, names);
      }
      if (node.type === "for_statement" || node.type === "for_in_clause") {
        const names = boundNames(node.childForFieldName("left") ?? node);
        const source = node.childForFieldName("right");
        if (source && carriedBy(source, tainted) !== undefined) for (const name of names) tainted.add(name);
      }
    },
    exit(node) {
      const restore = taken.get(node.id);
      if (restore) for (const name of restore) tainted.add(name);
      // `if not x.isdigit(): abort(400)`: when the check fails the function stops, so after the if the value is checked
      if (node.type === "if_statement" && node.namedChildren.every((c) => c.type !== "else_clause" && c.type !== "elif_clause")) {
        const guard = conditionGuard(node.childForFieldName("condition"));
        if (guard.no.length > 0 && alwaysExits(node.childForFieldName("consequence"))) for (const name of guard.no) tainted.delete(name);
      }
      switch (node.type) {
        case "assignment":
          assign(node.childForFieldName("left"), node.childForFieldName("right"), false);
          break;
        case "augmented_assignment":
          assign(node.childForFieldName("left"), node.childForFieldName("right"), true);
          break;
        case "call":
          handlers.onCall?.(node, tainted);
          break;
        case "return_statement":
          handlers.onReturn?.(node, tainted);
          break;
        default:
          break;
      }
    },
  });
}
