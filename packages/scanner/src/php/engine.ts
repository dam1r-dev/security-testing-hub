import { checkBudget } from "../budget";
import { SyntaxNode } from "../parsers/utils";

/**
 * Taint tracking for PHP (plain scripts, Laravel, Symfony). The same idea as the Python engine: statements in the order they run,
 * a set of variables that hold the caller's text, a few ways of building text that carry it on, a few calls that clean it.
 *
 *   $name = $_GET['name'];                         // $name is the caller's
 *   $sql = "SELECT * FROM users WHERE n = '$name'"; // so is $sql
 *   mysqli_query($conn, $sql);                      // a sink that is handed it
 *
 * The top level of a script is a scope of its own (most small PHP code is a script, not a function). Walks are iterative.
 */

const SUPERGLOBAL = new Set(["$_GET", "$_POST", "$_REQUEST", "$_COOKIE", "$_FILES"]);
// `$_SERVER` holds the server's own facts too; only the keys a caller can write count.
const SERVER_KEY = /^(?:HTTP_\w+|REQUEST_URI|QUERY_STRING|PATH_INFO|PHP_SELF|ORIG_PATH_INFO|PATH_TRANSLATED|HTTP_HOST)$/;
// Laravel / Symfony: $request->input("x"), $request->get("x"), $request->all(), $request->name
const REQUEST_VARIABLE = /^\$(?:request|req)$/;
const REQUEST_METHOD = new Set(["input", "get", "query", "post", "all", "only", "except", "route", "cookie", "header", "file", "json", "getContent", "string", "str", "collect", "validated", "safe", "bearerToken", "getPathInfo", "getQueryString", "getRequestUri", "path", "url", "fullUrl", "userAgent", "ip"]);

const CLEANING_FUNCTION = new Set([
  "intval", "floatval", "doubleval", "boolval", "is_numeric", "is_int", "ctype_digit", "ctype_alnum", "abs", "round", "floor", "ceil", "count", "strlen", "sizeof",
  "htmlspecialchars", "htmlentities", "esc_html", "esc_attr", "esc_url", "esc_js", "e", "strip_tags", "filter_var", "filter_input", "urlencode", "rawurlencode",
  "escapeshellarg", "escapeshellcmd", "mysqli_real_escape_string", "mysql_real_escape_string", "pg_escape_string", "pg_escape_literal", "sqlite_escape_string",
  "basename", "realpath", "md5", "sha1", "crc32", "hash", "password_hash", "password_verify", "uniqid", "json_encode", "base_convert", "bin2hex", "dechex",
  "in_array", "array_key_exists", "isset", "empty", "is_array", "is_string", "preg_match", "preg_quote", "sanitize_text_field", "sanitize_file_name",
  "wp_kses", "absint", "wp_unslash_clean", "url", "route", "asset", "action",
]);
const PASS_THROUGH_FUNCTION = new Set([
  "trim", "rtrim", "ltrim", "chop", "strtolower", "strtoupper", "ucfirst", "ucwords", "lcfirst", "substr", "mb_substr", "str_replace", "str_ireplace", "substr_replace",
  "sprintf", "vsprintf", "implode", "join", "urldecode", "rawurldecode", "base64_decode", "stripslashes", "html_entity_decode", "htmlspecialchars_decode", "nl2br",
  "strrev", "str_pad", "preg_replace", "json_decode", "strval", "addslashes", "wordwrap", "str_repeat", "array_values", "array_merge", "array_map", "array_filter",
  "explode", "str_split", "preg_split", "mb_strtolower", "mb_strtoupper", "utf8_decode", "utf8_encode", "iconv", "nl_langinfo", "trim_all", "wp_unslash", "stripcslashes",
  "end", "reset", "current", "array_pop", "array_shift", "array_key_first", "array_slice", "compact", "func_get_args",
]);
const INTEGER_CAST = new Set(["int", "integer", "float", "double", "real", "bool", "boolean"]);

export interface Names {
  has(name: string): boolean;
}

export function isRequestObject(node: SyntaxNode): boolean {
  if (node.type === "variable_name") return REQUEST_VARIABLE.test(node.text);
  if (node.type === "function_call_expression") return node.childForFieldName("function")?.text === "request";
  if (node.type === "scoped_call_expression") return /^(?:Request|Input)$/.test(node.childForFieldName("scope")?.text ?? "");
  return false;
}

export function calleeName(call: SyntaxNode): string {
  if (call.type === "function_call_expression") return (call.childForFieldName("function")?.text ?? "").replace(/^\\/, "");
  if (call.type === "member_call_expression") return call.childForFieldName("name")?.text ?? "";
  if (call.type === "scoped_call_expression") return `${call.childForFieldName("scope")?.text ?? ""}::${call.childForFieldName("name")?.text ?? ""}`;
  return "";
}

/** The argument expressions of a call (the `argument` wrappers removed). */
export function argumentsOf(call: SyntaxNode): SyntaxNode[] {
  const list = call.childForFieldName("arguments") ?? call.namedChildren.find((c) => c.type === "arguments");
  const out: SyntaxNode[] = [];
  for (const arg of list?.namedChildren ?? []) {
    if (arg.type === "comment") continue;
    const inner = arg.type === "argument" ? arg.namedChild(arg.namedChildCount - 1) : arg;
    if (inner) out.push(inner);
  }
  return out;
}

export function isSuperglobalSource(node: SyntaxNode): boolean {
  if (node.type === "variable_name") return SUPERGLOBAL.has(node.text);
  if (node.type === "subscript_expression") {
    const base = node.namedChild(0);
    if (!base || base.type !== "variable_name") return false;
    if (SUPERGLOBAL.has(base.text)) return true;
    if (base.text === "$_SERVER") {
      const key = node.namedChild(1);
      return key?.type === "string" && SERVER_KEY.test(key.text.slice(1, -1));
    }
  }
  return false;
}

/** Names a pattern binds: `$a`, `[$a, $b]`, `list($a, $b)`. */
export function boundNames(pattern: SyntaxNode): string[] {
  switch (pattern.type) {
    case "variable_name":
      return [pattern.text];
    case "array_creation_expression":
    case "list_literal":
    case "array_element_initializer":
    case "pair":
      return pattern.namedChildren.flatMap(boundNames);
    default:
      return [];
  }
}

function pushAll(stack: SyntaxNode[], nodes: Iterable<SyntaxNode>): void {
  for (const node of nodes) stack.push(node);
}

/** Which part of `expression` carries a tainted value, as text, or undefined when none does. */
export function carriedBy(expression: SyntaxNode, tainted: Names): string | undefined {
  const stack: SyntaxNode[] = [expression];
  while (stack.length > 0) {
    const node = stack.pop() as SyntaxNode;
    checkBudget();
    if (isSuperglobalSource(node)) return node.text.length > 60 ? `${node.text.slice(0, 57)}...` : node.text;
    switch (node.type) {
      case "variable_name":
        if (tainted.has(node.text)) return node.text;
        break;
      case "subscript_expression": {
        // $_FILES["f"]["tmp_name"] is a path PHP chose, and "size" / "error" are numbers: only the name and the type are the caller's
        const key = node.namedChild(1);
        if (key?.type === "string" && /^(?:tmp_name|size|error)$/.test(key.text.slice(1, -1))) break;
        const base = node.namedChild(0);
        if (base) stack.push(base);
        break;
      }
      case "member_access_expression": {
        const object = node.childForFieldName("object");
        if (object && isRequestObject(object)) return node.text;
        if (object) stack.push(object);
        break;
      }
      case "member_call_expression": {
        const object = node.childForFieldName("object");
        const method = node.childForFieldName("name")?.text ?? "";
        if (object && isRequestObject(object) && REQUEST_METHOD.has(method)) return node.text.length > 60 ? `${node.text.slice(0, 57)}...` : node.text;
        if (object && /^(?:input|get|query|post|all|only|except|route|header|cookie|first|pluck|toArray|value|string)$/.test(method)) stack.push(object);
        break;
      }
      case "scoped_call_expression": {
        if (isRequestObject(node) && REQUEST_METHOD.has(node.childForFieldName("name")?.text ?? "")) return node.text.length > 60 ? `${node.text.slice(0, 57)}...` : node.text;
        break;
      }
      case "function_call_expression": {
        const name = calleeName(node);
        const lower = name.toLowerCase();
        if (name === "request") return node.text;
        if (name === "file_get_contents" && /php:\/\/input/.test(node.text)) return "php://input";
        if (name === "getallheaders" || name === "apache_request_headers") return `${name}()`;
        if (CLEANING_FUNCTION.has(lower)) break;
        if (PASS_THROUGH_FUNCTION.has(lower)) pushAll(stack, argumentsOf(node));
        break;
      }
      case "encapsed_string":
      case "heredoc":
      case "heredoc_body":
      case "shell_command_expression":
        for (const part of node.namedChildren) if (part.type !== "string_content" && part.type !== "escape_sequence" && part.type !== "heredoc_start" && part.type !== "heredoc_end") stack.push(part);
        break;
      case "cast_expression": {
        const type = node.childForFieldName("type")?.text.toLowerCase() ?? "";
        if (INTEGER_CAST.has(type)) break;
        const value = node.childForFieldName("value");
        if (value) stack.push(value);
        break;
      }
      case "conditional_expression": {
        const body = node.childForFieldName("body");
        const alternative = node.childForFieldName("alternative");
        if (body) stack.push(body);
        if (alternative) stack.push(alternative);
        else {
          const condition = node.childForFieldName("condition"); // `$a ?: $b`
          if (condition) stack.push(condition);
        }
        break;
      }
      case "binary_expression": {
        const operator = node.childForFieldName("operator")?.text ?? "";
        if (/^(?:==|===|!=|!==|<|>|<=|>=|<>|&&|\|\||and|or|xor|instanceof)$/.test(operator)) break; // a comparison is a truth value, not text
        const left = node.childForFieldName("left");
        const right = node.childForFieldName("right");
        if (left) stack.push(left);
        if (right) stack.push(right);
        break;
      }
      case "parenthesized_expression":
      case "unary_op_expression":
      case "argument":
      case "array_creation_expression":
      case "array_element_initializer":
      case "pair":
      case "reference_modifier":
      case "by_ref":
      case "sequence_expression":
        pushAll(stack, node.namedChildren);
        break;
      default:
        break;
    }
  }
  return undefined;
}

export interface WalkHandlers {
  enter?(node: SyntaxNode): void;
  exit?(node: SyntaxNode): void;
}

const SCOPE_BOUNDARY = new Set(["function_definition", "method_declaration", "anonymous_function", "arrow_function", "class_declaration", "interface_declaration", "trait_declaration"]);

/** Walks the statements of one scope (a function body, or the top level of a file), not the functions and classes inside it. */
export function walkScope(scope: SyntaxNode, handlers: WalkHandlers): void {
  const stack: Array<{ node: SyntaxNode; leaving: boolean }> = [];
  const startChildren = scope.type === "program" ? scope.namedChildren : [scope.childForFieldName("body") ?? scope];
  for (let i = startChildren.length - 1; i >= 0; i--) stack.push({ node: startChildren[i] as SyntaxNode, leaving: false });
  while (stack.length > 0) {
    const { node, leaving } = stack.pop() as { node: SyntaxNode; leaving: boolean };
    checkBudget();
    if (leaving) {
      handlers.exit?.(node);
      continue;
    }
    if (SCOPE_BOUNDARY.has(node.type) && node.id !== scope.id) continue;
    handlers.enter?.(node);
    stack.push({ node, leaving: true });
    const children = node.namedChildren;
    for (let i = children.length - 1; i >= 0; i--) stack.push({ node: children[i] as SyntaxNode, leaving: false });
  }
}

/**
 * Runs `onNode` for every node that can be a dangerous use (calls, `include`, `echo`, `print`, `exit`, backticks) with the variables that
 * are the caller's AT THAT POINT. Assignments and loops update the set as the walk goes.
 */
export function trackTaint(scope: SyntaxNode, origins: Iterable<string>, onNode: (node: SyntaxNode, tainted: Names) => void): void {
  const tainted = new Set(origins);
  const assign = (target: SyntaxNode | null, value: SyntaxNode | null, additive: boolean): void => {
    if (!target || !value) return;
    const names = boundNames(target);
    if (names.length === 0) return;
    const carries = carriedBy(value, tainted) !== undefined;
    for (const name of names) {
      if (carries) tainted.add(name);
      else if (!additive) tainted.delete(name);
    }
  };
  walkScope(scope, {
    enter(node) {
      if (node.type === "foreach_statement") {
        const [iterated, ...rest] = node.namedChildren;
        if (iterated && carriedBy(iterated, tainted) !== undefined) {
          for (const child of rest) if (child.type === "variable_name" || child.type === "pair") for (const name of boundNames(child)) tainted.add(name);
        }
      }
    },
    exit(node) {
      switch (node.type) {
        case "assignment_expression":
          assign(node.childForFieldName("left"), node.childForFieldName("right"), false);
          break;
        case "augmented_assignment_expression":
          assign(node.childForFieldName("left"), node.childForFieldName("right"), true);
          break;
        case "function_call_expression":
        case "member_call_expression":
        case "scoped_call_expression":
        case "object_creation_expression":
        case "include_expression":
        case "include_once_expression":
        case "require_expression":
        case "require_once_expression":
        case "echo_statement":
        case "print_intrinsic":
        case "exit_statement":
        case "shell_command_expression":
          onNode(node, tainted);
          break;
        case "expression_statement":
          // `<p><?= $value ?></p>`: the short echo tag is an echo
          if (node.previousNamedSibling?.type === "php_tag" && node.previousNamedSibling.text === "<?=") onNode(node, tainted);
          break;
        default:
          break;
      }
    },
  });
}
