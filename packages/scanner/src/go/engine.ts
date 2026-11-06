import { checkBudget } from "../budget";
import { SyntaxNode } from "../parsers/utils";

/**
 * Taint tracking for Go (net/http, gin, echo, fiber, chi, gorilla/mux, httprouter). One function at a time, in the order the statements run:
 *
 *   name := r.URL.Query().Get("name")      // name is the caller's
 *   q := "SELECT ... '" + name + "'"       // so is q
 *   db.Query(q)                            // a sink that is handed it
 *
 * What carries the value on: `+`, `fmt.Sprintf`, `strings.*` that give text back, conversions (`string(x)`, `[]byte(x)`), fields, indexes and
 * slices of a tainted value, struct literals that hold one, methods such as `.String()` / `.Get()`. What stops it: a call that cleans
 * (`strconv.Atoi`, `filepath.Base`, `url.QueryEscape`, `html.EscapeString`, `uuid.Parse`...), and a reassignment to something clean. Any
 * other call is not followed here (an unknown function may do anything with its argument): helpers are followed by project.ts.
 * Walks are iterative: a hostile file with a 60 000-deep expression must not overflow the stack.
 */

/** The names in a function's signature that hold the request or a framework context. */
export interface Roots {
  /** `r *http.Request` */
  requests: ReadonlySet<string>;
  /** gin `c *gin.Context`, echo `c echo.Context`, fiber `c *fiber.Ctx`, fasthttp `ctx *fasthttp.RequestCtx` */
  contexts: ReadonlySet<string>;
  /** httprouter `ps httprouter.Params` */
  params: ReadonlySet<string>;
  /** `w http.ResponseWriter` */
  writers: ReadonlySet<string>;
}

export const NO_ROOTS: Roots = { requests: new Set(), contexts: new Set(), params: new Set(), writers: new Set() };

export function hasRoots(roots: Roots): boolean {
  return roots.requests.size > 0 || roots.contexts.size > 0 || roots.params.size > 0;
}

const REQUEST_TYPE = /^\*?(?:http\.)?Request$/;
const CONTEXT_TYPE = /^\*?(?:gin\.Context|echo\.Context|fiber\.Ctx|fasthttp\.RequestCtx|app\.RequestContext|iris\.Context)$/;
const PARAMS_TYPE = /^(?:httprouter\.Params|\*?router\.Params)$/;
const WRITER_TYPE = /^(?:http\.)?ResponseWriter$/;

/** The parameter names of a function (a declaration, a method or a literal), grouped by what they are. */
export function rootsOf(fn: SyntaxNode): Roots {
  const requests = new Set<string>();
  const contexts = new Set<string>();
  const params = new Set<string>();
  const writers = new Set<string>();
  const list = fn.childForFieldName("parameters");
  for (const declaration of list?.namedChildren ?? []) {
    if (declaration.type !== "parameter_declaration") continue;
    const type = declaration.childForFieldName("type")?.text.replace(/\s+/g, "") ?? "";
    const names = declaration.namedChildren.filter((c) => c.type === "identifier").map((c) => c.text);
    for (const name of names) {
      if (name === "_") continue;
      if (REQUEST_TYPE.test(type)) requests.add(name);
      else if (CONTEXT_TYPE.test(type)) contexts.add(name);
      else if (PARAMS_TYPE.test(type)) params.add(name);
      else if (WRITER_TYPE.test(type)) writers.add(name);
    }
  }
  return { requests, contexts, params, writers };
}

// Methods of a framework context that hand out what the caller sent.
// (`c.Get("key")` is left out: in gin and echo it reads a value the application stored.)
const CONTEXT_SOURCE =
  /^(?:Query|QueryArray|QueryMap|DefaultQuery|GetQuery|GetQueryArray|GetQueryMap|Param|Params|PostForm|PostFormArray|PostFormMap|DefaultPostForm|GetPostForm|GetPostFormArray|GetHeader|GetRawData|Cookie|FormFile|MultipartForm|FormValue|FormParams|QueryParam|QueryParams|QueryString|ParamValues|FormValues|Body|Cookies|Path|OriginalURL|BaseURL|Hostname|AllParams|Queries|Referer|UserAgent|Host|URI|QueryArgs|PostArgs|UserValue|FullPath|RawPath|URLParam|PathParam|PathParams|ReadBody)$/;
// What a request offers that is not text of the caller's.
const SAFE_REQUEST_MEMBER = /^(?:Context|Method|Proto|ProtoMajor|ProtoMinor|TLS|ParseForm|ParseMultipartForm|WithContext|Clone|Close|ContentLength|Cancel|Response|GetBody|PathValue|SetPathValue|Pattern|Write|WriteProxy)$/;

export interface Chain {
  root: string;
  members: string[];
}

/** `r.URL.Query().Get("x")` -> root `r`, members `URL`, `Query`, `Get`. Undefined when the expression does not start from a name. */
export function chainOf(node: SyntaxNode): Chain | undefined {
  const members: string[] = [];
  let current: SyntaxNode | null = node;
  for (let steps = 0; current && steps < 64; steps++) {
    switch (current.type) {
      case "identifier":
        return { root: current.text, members: members.reverse() };
      case "selector_expression":
        members.push(current.childForFieldName("field")?.text ?? "");
        current = current.childForFieldName("operand");
        break;
      case "call_expression":
        current = current.childForFieldName("function");
        break;
      case "index_expression":
      case "slice_expression":
      case "parenthesized_expression":
      case "type_assertion_expression":
        current = current.childForFieldName("operand") ?? current.namedChild(0);
        break;
      case "unary_expression":
        current = current.childForFieldName("operand");
        break;
      default:
        return undefined;
    }
  }
  return undefined;
}

/**
 * What the request line carries: it starts with "/", so it is a path, not a host. It cannot choose the server of an outgoing request
 * (SSRF), though it is the caller's text for every other rule.
 */
export const PATH_SOURCE = /RequestURI|URL\.Path|EscapedPath|RawPath/;

/** A value the caller sent: `r.URL.Query().Get("q")`, `r.FormValue("id")`, `c.Query("id")`, `c.Param("id")`, `chi.URLParam(r, "id")`. */
export function isRequestSource(node: SyntaxNode, roots: Roots): boolean {
  if (node.type === "call_expression") {
    const callee = node.childForFieldName("function")?.text ?? "";
    if (/^(?:chi\.URLParam|chi\.URLParamFromCtx|mux\.Vars|gorillamux\.Vars|httprouter\.ParamsFromContext|echo\.GetPathParam)$/.test(callee)) return true;
    if (/(?:^|\.)(?:URLParam|URLParamFromCtx)$/.test(callee) && roots.requests.size > 0) return true;
  }
  if (node.type !== "call_expression" && node.type !== "selector_expression" && node.type !== "index_expression" && node.type !== "slice_expression") return false;
  const chain = chainOf(node);
  if (!chain || chain.members.length === 0) return false;
  const first = chain.members[0] as string;
  if (roots.requests.has(chain.root)) return !SAFE_REQUEST_MEMBER.test(first);
  if (roots.params.has(chain.root)) return first === "ByName";
  if (roots.contexts.has(chain.root)) {
    // c.Request.URL.Query().Get("q"): the request itself is not text, what hangs off it is
    if (first === "Request" || first === "Req") return chain.members.length > 1 && !SAFE_REQUEST_MEMBER.test(chain.members[1] as string);
    return CONTEXT_SOURCE.test(first);
  }
  return false;
}

/** The text of a call's callee: `db.Query`, `fmt.Sprintf`, `exec.Command`, `h.db.QueryRow`. */
export function calleeText(call: SyntaxNode): string {
  return call.childForFieldName("function")?.text.replace(/\s+/g, "") ?? "";
}

/** The arguments of a call, in order (comments and the type arguments of a generic call left out). */
export function callArguments(call: SyntaxNode): SyntaxNode[] {
  return (call.childForFieldName("arguments")?.namedChildren ?? []).filter((a) => a.type !== "comment");
}

const CLEANING_FUNCTION =
  /^(?:strconv\.\w+|filepath\.Base|path\.Base|filepath\.Ext|path\.Ext|filepath\.IsAbs|filepath\.Rel|securejoin\.SecureJoin|url\.QueryEscape|url\.PathEscape|template\.HTMLEscapeString|template\.JSEscapeString|template\.URLQueryEscaper|html\.EscapeString|html\.UnescapeString0|uuid\.Parse|uuid\.MustParse|uuid\.FromString|ulid\.Parse|len|cap|int|int8|int16|int32|int64|uint|uint8|uint16|uint32|uint64|float32|float64|bool|rune|byte|time\.Parse|time\.ParseDuration|net\.ParseIP|mail\.ParseAddress|regexp\.QuoteMeta|bluemonday\.\w+\.Sanitize|\w+\.Sanitize|\w+\.SanitizeBytes|sanitize\w*|validate\w*|escape\w*|bcrypt\.\w+|sha\d*\.\w+|md5\.\w+|hex\.EncodeToString|base64\.\w+\.EncodeToString|hash\w*)$/;
// Calls that give back (a form of) their arguments: the value is still the caller's.
const PASS_THROUGH_FUNCTION =
  /^(?:string|\[\]byte|\[\]rune|fmt\.Sprint|fmt\.Sprintf|fmt\.Sprintln|fmt\.Errorf|errors\.New|path\.Join|path\.Clean|filepath\.Join|filepath\.Clean|filepath\.ToSlash|filepath\.FromSlash|filepath\.Abs|strings\.(?:ToLower|ToUpper|ToTitle|Title|TrimSpace|Trim|TrimLeft|TrimRight|TrimPrefix|TrimSuffix|TrimFunc|Replace|ReplaceAll|Join|Split|SplitN|SplitAfter|Fields|Repeat|Map|Clone|Cut)|bytes\.(?:ToLower|ToUpper|TrimSpace|Trim|Replace|ReplaceAll|Join|Split)|strings\.NewReader|strings\.NewReplacer|bytes\.NewBufferString|bytes\.NewBuffer|bytes\.NewReader|io\.ReadAll|ioutil\.ReadAll|io\.NopCloser|ioutil\.NopCloser|bufio\.NewReader|bufio\.NewScanner|url\.Parse|url\.ParseRequestURI|url\.PathUnescape|url\.QueryUnescape|template\.HTML|template\.JS|template\.CSS|template\.HTMLAttr|template\.URL|template\.JSStr|template\.Srcset|base64\.\w+\.DecodeString|hex\.DecodeString|json\.RawMessage|sql\.Named|text|append|copy)$/;
// Methods of a tainted receiver that give back text built from it.
const PROPAGATING_METHOD = new Set([
  "String", "Bytes", "Get", "GetString", "Query", "Values", "Value", "Text", "Interface", "Encode", "Path", "RawQuery", "Fragment", "Hostname", "Port",
  "Trim", "TrimSpace", "ToLower", "ToUpper", "Split", "Join", "Replace", "ReplaceAll", "Cookies", "Cookie", "Header", "Form", "PostForm", "Read",
  "ReadString", "ReadBytes", "ReadAll", "Scan", "Next", "First", "Last", "Peek", "Name", "Filename", "Open", "Sanitize", "Clone", "Raw", "Param", "Params",
]);
const BUILDING_METHOD = new Set(["Join", "Replace", "ReplaceAll", "Write", "WriteString", "Sprintf"]);

/**
 * Which part of `expression` carries a tainted value, as text (a name or a request expression), or undefined when none does.
 * `tainted` is the set of names that are the caller's right now.
 */
export function carriedBy(expression: SyntaxNode, tainted: ReadonlySet<string>, roots: Roots, ignorePaths = false): string | undefined {
  const stack: SyntaxNode[] = [expression];
  while (stack.length > 0) {
    const node = stack.pop() as SyntaxNode;
    checkBudget();
    switch (node.type) {
      case "identifier":
        if (tainted.has(node.text)) return node.text;
        break;
      case "selector_expression":
      case "index_expression":
      case "slice_expression": {
        if (isRequestSource(node, roots) && !(ignorePaths && PATH_SOURCE.test(node.text))) return node.text.length > 60 ? `${node.text.slice(0, 57)}...` : node.text;
        // a field of a tainted struct, an element of a tainted slice, a map value looked up with a tainted key is not the key
        const base = node.childForFieldName("operand");
        if (base) stack.push(base);
        break;
      }
      case "call_expression": {
        if (isRequestSource(node, roots) && !(ignorePaths && PATH_SOURCE.test(node.text))) return node.text.length > 60 ? `${node.text.slice(0, 57)}...` : node.text;
        const callee = node.childForFieldName("function");
        if (!callee) break;
        const name = callee.text.replace(/\s+/g, "");
        if (CLEANING_FUNCTION.test(name)) break;
        const args = callArguments(node);
        if (callee.type === "selector_expression") {
          const method = callee.childForFieldName("field")?.text ?? "";
          const receiver = callee.childForFieldName("operand");
          if (PASS_THROUGH_FUNCTION.test(name)) {
            for (const a of args) stack.push(a);
          } else if (PROPAGATING_METHOD.has(method) && receiver) {
            stack.push(receiver);
            if (BUILDING_METHOD.has(method)) for (const a of args) stack.push(a);
          }
        } else if (PASS_THROUGH_FUNCTION.test(name)) {
          for (const a of args) stack.push(a);
        }
        break;
      }
      case "type_conversion_expression":
        // []byte(x), []rune(x)
        stack.push(node.childForFieldName("operand") ?? node.namedChildren[node.namedChildren.length - 1] ?? node);
        break;
      case "binary_expression": {
        const operator = node.childForFieldName("operator")?.text;
        if (operator === "+") {
          const left = node.childForFieldName("left");
          const right = node.childForFieldName("right");
          if (right) stack.push(right);
          if (left) stack.push(left);
        }
        break;
      }
      case "unary_expression":
        // &x, *x, <-ch (a received value is not followed)
        if (node.childForFieldName("operator")?.text !== "<-") {
          const operand = node.childForFieldName("operand");
          if (operand) stack.push(operand);
        }
        break;
      case "parenthesized_expression":
      case "type_assertion_expression":
        stack.push(node.childForFieldName("operand") ?? node.namedChild(0) ?? node);
        break;
      case "composite_literal": {
        // []string{x}, map[string]string{"a": x} hold the text; a struct (`&UserModel{Username: x}`, gin.H) is not text: a query
        // condition built from one is a parameterised lookup, not a string spliced into SQL
        const kind = node.childForFieldName("type")?.type ?? "";
        if (/^(?:slice_type|array_type|implicit_length_array_type|map_type)$/.test(kind)) {
          const body = node.childForFieldName("body");
          if (body) stack.push(body);
        }
        break;
      }
      case "literal_value":
      case "literal_element":
      case "keyed_element":
      case "element":
      case "expression_list":
        for (const child of node.namedChildren) if (child.type !== "type_identifier" && child.type !== "qualified_type") stack.push(child);
        break;
      default:
        break;
    }
  }
  return undefined;
}

/** Names an assignment target binds or writes: `a`, `a, b`, `s.field` (the struct), `m["k"]` (the map). */
export function targetNames(target: SyntaxNode): string[] {
  switch (target.type) {
    case "identifier":
      return target.text === "_" ? [] : [target.text];
    case "expression_list":
      return target.namedChildren.flatMap(targetNames);
    case "selector_expression":
    case "index_expression": {
      const base = target.childForFieldName("operand");
      return base ? targetNames(base) : [];
    }
    case "unary_expression":
    case "parenthesized_expression": {
      const base = target.childForFieldName("operand") ?? target.namedChild(0);
      return base ? targetNames(base) : [];
    }
    default:
      return [];
  }
}

/** Walks a function's own statements, reporting events in the order they happen. Closures are part of the function (they share its names). */
export interface WalkHandlers {
  /** Before the children of a node: used for loops, whose variable is tainted by what they iterate over. */
  enter?(node: SyntaxNode): void;
  /** After the children: assignments take effect, calls are checked, `return` values are looked at. */
  exit?(node: SyntaxNode): void;
}

export function walkFunction(fn: SyntaxNode, handlers: WalkHandlers, skipLiteral?: (literal: SyntaxNode) => boolean): void {
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
    // a handler written inline (`http.HandleFunc("/", func(w, r) {...})`) is a function of its own and is looked at separately
    if (node.type === "func_literal" && skipLiteral?.(node)) continue;
    handlers.enter?.(node);
    stack.push({ node, leaving: true });
    const children = node.namedChildren;
    for (let i = children.length - 1; i >= 0; i--) stack.push({ node: children[i] as SyntaxNode, leaving: false });
  }
}

// `c.ShouldBindJSON(&input)`, `c.BodyParser(&input)`, `c.Bind(&input)`: the variable is filled from the request.
const BINDER = /^(?:ShouldBind\w*|Bind\w*|MustBindWith|BodyParser|QueryParser|ParamsParser|ReqHeaderParser|CookieParser|ReadJSON|ReadForm|ReadQuery|ReadBody|ReadParams|BindJSON|BindQuery|BindForm)$/;

/** The variable a binding call fills (`&input` -> `input`), when the call reads from the request. */
export function boundByCall(call: SyntaxNode, tainted: ReadonlySet<string>, roots: Roots): string[] {
  const callee = call.childForFieldName("function");
  if (!callee) return [];
  const args = callArguments(call);
  const name = callee.text.replace(/\s+/g, "");
  if (callee.type === "selector_expression") {
    const method = callee.childForFieldName("field")?.text ?? "";
    const receiver = callee.childForFieldName("operand");
    const chain = chainOf(callee);
    // c.ShouldBindJSON(&x)
    if (BINDER.test(method) && chain && roots.contexts.has(chain.root)) return args[0] ? targetNames(args[0]) : [];
    // json.NewDecoder(r.Body).Decode(&x), xml.NewDecoder(r.Body).Decode(&x), schema.NewDecoder().Decode(&x, r.Form)
    if (method === "Decode" && receiver && args[0]) {
      const source = receiver.type === "call_expression" ? callArguments(receiver)[0] : undefined;
      if (source && carriedBy(source, tainted, roots) !== undefined) return targetNames(args[0]);
      if (args[1] && carriedBy(args[1], tainted, roots) !== undefined) return targetNames(args[0]);
    }
  }
  // json.Unmarshal(body, &x), yaml.Unmarshal, xml.Unmarshal
  if (/^(?:json|xml|yaml|toml|jsoniter|msgpack|sonic)\.Unmarshal$/.test(name) && args[0] && args[1] && carriedBy(args[0], tainted, roots) !== undefined) return targetNames(args[1]);
  // r.ParseForm() leaves the values in r.Form: those are sources by themselves
  return [];
}

/**
 * Runs `onCall` for every call of the function, with the names that are the caller's AT THAT POINT (assignments and loops update the set
 * as the walk goes; a name assigned something clean is no longer tainted). `initial` names are tainted from the start (the parameters of a
 * helper that is being summarised).
 */
export function trackTaint(
  fn: SyntaxNode,
  roots: Roots,
  initial: ReadonlySet<string>,
  handlers: {
    /** `pathOnly`: the tainted names whose only source is the request line (a path, see PATH_SOURCE). */
    onCall?(call: SyntaxNode, tainted: ReadonlySet<string>, pathOnly: ReadonlySet<string>): void;
    onReturn?(statement: SyntaxNode, tainted: ReadonlySet<string>): void;
  },
): void {
  const tainted = new Set(initial);
  const pathOnly = new Set<string>();
  const assign = (targets: SyntaxNode | null, values: SyntaxNode | null, additive: boolean): void => {
    if (!targets || !values) return;
    const left = targets.type === "expression_list" ? targets.namedChildren : [targets];
    const right = values.type === "expression_list" ? values.namedChildren : [values];
    for (let i = 0; i < left.length; i++) {
      const target = left[i] as SyntaxNode;
      const names = targetNames(target);
      if (names.length === 0) continue;
      // `a, b := x, y` pairs up; `rows, err := f(x)` gives every name the one value
      const source = left.length === right.length ? (right[i] as SyntaxNode) : right.length === 1 ? (right[0] as SyntaxNode) : undefined;
      const carries = source ? carriedBy(source, tainted, roots) !== undefined : right.some((v) => carriedBy(v, tainted, roots) !== undefined);
      const beyondPath = new Set([...tainted].filter((n) => !pathOnly.has(n)));
      const onlyPath = carries && (source ? carriedBy(source, beyondPath, roots, true) === undefined : right.every((v) => carriedBy(v, beyondPath, roots, true) === undefined));
      // `err` and the like are never the caller's text
      for (const name of names) {
        if (carries) {
          if (!(left.length > 1 && right.length === 1 && name === "err") && !(left.length > 1 && right.length === 1 && i === left.length - 1 && /^(?:err|ok|found|exists)$/.test(name))) {
            tainted.add(name);
            if (onlyPath) pathOnly.add(name);
            else pathOnly.delete(name);
          }
        } else if (!additive && target.type === "identifier") {
          tainted.delete(name); // `x = clean`: no longer the caller's text
          pathOnly.delete(name);
        }
      }
    }
  };
  walkFunction(
    fn,
    {
      enter(node) {
        if (node.type === "range_clause") {
          const source = node.childForFieldName("right");
          const left = node.childForFieldName("left");
          if (source && left && carriedBy(source, tainted, roots) !== undefined) for (const name of targetNames(left)) tainted.add(name);
        }
      },
      exit(node) {
        switch (node.type) {
          case "short_var_declaration":
            assign(node.childForFieldName("left"), node.childForFieldName("right"), false);
            break;
          case "assignment_statement": {
            const operator = node.childForFieldName("operator")?.text ?? "=";
            assign(node.childForFieldName("left"), node.childForFieldName("right"), operator !== "=");
            break;
          }
          case "var_spec": {
            const value = node.childForFieldName("value");
            const names = node.namedChildren.filter((c) => c.type === "identifier");
            if (value && names.length > 0) {
              const right = value.type === "expression_list" ? value.namedChildren : [value];
              names.forEach((nameNode, i) => {
                const source = names.length === right.length ? right[i] : right.length === 1 ? right[0] : undefined;
                if (source && carriedBy(source, tainted, roots) !== undefined) tainted.add(nameNode.text);
              });
            }
            break;
          }
          case "call_expression":
            for (const name of boundByCall(node, tainted, roots)) tainted.add(name);
            handlers.onCall?.(node, tainted, pathOnly);
            break;
          case "return_statement":
            handlers.onReturn?.(node, tainted);
            break;
          default:
            break;
        }
      },
    },
    (literal) => hasRoots(rootsOf(literal)),
  );
}
