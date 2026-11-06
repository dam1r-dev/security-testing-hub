import { checkBudget } from "../budget";
import { SyntaxNode } from "../parsers/utils";

/**
 * Taint tracking for Java (Servlets, Spring MVC / WebFlux controllers, JAX-RS, Micronaut, Spark, Javalin). One method at a time, in the
 * order the statements run:
 *
 *   String name = request.getParameter("name");           // name is the caller's
 *   String q = "SELECT ... '" + name + "'";               // so is q
 *   statement.executeQuery(q);                            // a sink that is handed it
 *
 * What carries the value on: `+`, `String.format`, `StringBuilder.append`, string methods (`trim`, `replace`...), getters of a tainted object,
 * casts, ternaries, `new File(x)`, `Paths.get(x)`, JSON mapping (`objectMapper.readValue(body, Dto.class)`). What stops it: a call that cleans
 * (`Integer.parseInt`, `UUID.fromString`, `HtmlUtils.htmlEscape`, `FilenameUtils.getName`...), and a reassignment to something clean. Any
 * other call is not followed here (an unknown method may do anything with its argument): helpers are followed by project.ts.
 * Walks are iterative: a hostile file with a 60 000-deep expression must not overflow the stack.
 */

export interface Roots {
  /** `HttpServletRequest request`, Spark `Request req`, Javalin `Context ctx`: calls on it hand out what the caller sent. */
  requests: ReadonlySet<string>;
  /** `HttpServletResponse response` */
  responses: ReadonlySet<string>;
  /** `PrintWriter out = response.getWriter()` */
  writers: ReadonlySet<string>;
  /** Parameters the framework fills from the request (`@RequestParam String name`, `@PathVariable`, `@RequestBody Dto body`, JAX-RS `@QueryParam`). */
  params: ReadonlySet<string>;
  /** For a call of a method declared in the project: the positions of the arguments whose value comes back out of it (`String bar = helper(x)`). */
  returns?: (call: SyntaxNode) => readonly number[] | undefined;
}

export const NO_ROOTS: Roots = { requests: new Set(), responses: new Set(), writers: new Set(), params: new Set() };

export function hasRoots(roots: Roots): boolean {
  return roots.requests.size > 0 || roots.params.size > 0;
}

const REQUEST_TYPE = /(?:^|\.)(?:Http)?ServletRequest(?:Wrapper)?$|(?:^|\.)(?:Native)?WebRequest$|(?:^|\.)ServerHttpRequest$|(?:^|\.)ServerRequest$/;
const RESPONSE_TYPE = /(?:^|\.)(?:Http)?ServletResponse(?:Wrapper)?$|(?:^|\.)ServerHttpResponse$/;
// Parameter annotations that mean "this value came from the request".
const SOURCE_ANNOTATION =
  /^(?:RequestParam|PathVariable|RequestBody|RequestHeader|CookieValue|ModelAttribute|RequestPart|MatrixVariable|QueryParam|PathParam|FormParam|HeaderParam|CookieParam|MatrixParam|BeanParam|QueryValue|Body|Header|CookieValue|FormDataParam|Param)$/;
const MAPPING_ANNOTATION = /^(?:(?:Get|Post|Put|Delete|Patch|Request)Mapping|GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|Path|Get|Post|Put|Delete|Patch|Head|Options|Trace)$/;
// Types Spring injects into a handler that are not the caller's text.
const FRAMEWORK_TYPE =
  /^(?:Model|ModelMap|ModelAndView|BindingResult|Errors|Principal|Authentication|HttpSession|Locale|Pageable|Sort|RedirectAttributes|UriComponentsBuilder|InputStream|OutputStream|Reader|Writer|TimeZone|ZoneId|HttpMethod|WebRequest|SessionStatus|HttpEntity|Void|Mono|Flux|SecurityContext|UserDetails|Jwt|Map<String,\s*Object>|(?:int|long|short|byte|double|float|boolean|char|Integer|Long|Short|Byte|Double|Float|Boolean|Character|UUID|BigDecimal|BigInteger|LocalDate|LocalDateTime|Instant|Date))$/;
const TEXT_TYPE = /^(?:String|CharSequence|Object|MultipartFile|String\[\]|List<String>|Set<String>|Collection<String>|Map<String,\s*String>|MultiValueMap<String,\s*String>|[A-Z]\w*(?:Dto|DTO|Request|Form|Command|Input|Payload|Params|Criteria|Filter|Body|Model|Query|Search))$/;

const NOT_TEXT_TYPE = /^(?:int|long|short|byte|double|float|boolean|char|Integer|Long|Short|Byte|Double|Float|Boolean|Character|UUID|BigDecimal|BigInteger|LocalDate|LocalDateTime|LocalTime|Instant|Date|ZonedDateTime|Duration)$/;

function annotationNames(modifiers: SyntaxNode | null | undefined): string[] {
  return (modifiers?.namedChildren ?? []).filter((c) => c.type === "annotation" || c.type === "marker_annotation").map((c) => c.childForFieldName("name")?.text.replace(/^.*\./, "") ?? "");
}

function isHandlerMethod(fn: SyntaxNode): boolean {
  const modifiers = fn.namedChildren.find((c) => c.type === "modifiers");
  return annotationNames(modifiers).some((a) => MAPPING_ANNOTATION.test(a));
}

/** Parameter names of a method, constructor or lambda, grouped by what they are. `fileText` tells Spark / Javalin lambdas (no types) from others. */
export function rootsOf(fn: SyntaxNode, fileText: string): Roots {
  const requests = new Set<string>();
  const responses = new Set<string>();
  const writers = new Set<string>();
  const params = new Set<string>();
  if (fn.type === "lambda_expression") {
    // Spark: get("/x", (req, res) -> {...}); Javalin: app.get("/x", ctx -> {...})
    const raw = fn.childForFieldName("parameters");
    const names = raw?.type === "identifier" ? [raw.text] : (raw?.namedChildren ?? []).map((c) => (c.type === "identifier" ? c.text : (c.childForFieldName("name")?.text ?? "")));
    if (/import\s+(?:static\s+)?(?:spark|io\.javalin|io\.vertx|ratpack)/.test(fileText)) {
      for (const name of names) {
        if (/^(?:req|request|ctx|context|rc)$/.test(name)) requests.add(name);
        else if (/^(?:res|response)$/.test(name)) responses.add(name);
      }
    }
  } else {
    const handler = isHandlerMethod(fn);
    for (const declaration of fn.childForFieldName("parameters")?.namedChildren ?? []) {
      if (declaration.type !== "formal_parameter" && declaration.type !== "spread_parameter") continue;
      const name = declaration.childForFieldName("name")?.text ?? declaration.namedChildren.find((c) => c.type === "variable_declarator")?.childForFieldName("name")?.text;
      const type = declaration.childForFieldName("type")?.text.replace(/\s+/g, "") ?? "";
      if (!name) continue;
      const annotations = annotationNames(declaration.namedChildren.find((c) => c.type === "modifiers"));
      if (REQUEST_TYPE.test(type) || (/^Request$/.test(type) && /import\s+spark/.test(fileText)) || (/^(?:Context|RoutingContext)$/.test(type) && /import\s+(?:io\.javalin|io\.vertx)/.test(fileText))) requests.add(name);
      else if (RESPONSE_TYPE.test(type) || (/^Response$/.test(type) && /import\s+spark/.test(fileText))) responses.add(name);
      else if (NOT_TEXT_TYPE.test(type)) continue; // a number, a boolean, a UUID, a date: it cannot carry text
      else if (annotations.some((a) => SOURCE_ANNOTATION.test(a))) params.add(name);
      else if (handler && annotations.length === 0 && !FRAMEWORK_TYPE.test(type) && TEXT_TYPE.test(type)) params.add(name); // Spring binds a plain parameter from the request
    }
  }
  // PrintWriter out = response.getWriter();
  const body = fn.childForFieldName("body");
  if (body && (responses.size > 0 || requests.size > 0)) {
    const stack: SyntaxNode[] = [body];
    while (stack.length > 0) {
      const node = stack.pop() as SyntaxNode;
      if (node.type === "variable_declarator") {
        const valueNode = node.childForFieldName("value");
        const value = valueNode?.text ?? "";
        if (/\.(?:getWriter|getOutputStream)\(\)$/.test(value)) writers.add(node.childForFieldName("name")?.text ?? "");
        // SeparateClassRequest scr = new SeparateClassRequest(request): a wrapper around the request hands out the same things
        if (valueNode?.type === "object_creation_expression" && /Request|Param|Wrapper|Input/i.test(valueNode.childForFieldName("type")?.text ?? "")) {
          const wrapped = argumentsOf(valueNode).some((a) => a.type === "identifier" && requests.has(a.text));
          if (wrapped) requests.add(node.childForFieldName("name")?.text ?? "");
        }
      }
      for (const child of node.namedChildren) if (child.type !== "class_body") stack.push(child);
    }
  }
  return { requests, responses, writers, params };
}

// Calls on the request object that hand out what the caller sent (servlet API, Spark, Javalin, Vert.x).
const REQUEST_SOURCE =
  /^(?:get\w*(?:Param|Parameter|Header|Cookie|Query)\w*|getParameter|getParameterValues|getParameterMap|getParameterNames|getHeader|getHeaders|getHeaderNames|getQueryString|getRequestURI|getRequestURL|getPathInfo|getPathTranslated|getCookies|getInputStream|getReader|getPart|getParts|getServletPath|getRemoteUser|getPathVariable|getReferer|queryParams|queryParam|queryParamsValues|queryMap|params|splat|body|bodyAsBytes|bodyAsClass|bodyValidator|cookie|cookies|headers|header|pathParam|pathParamMap|formParam|formParams|formParamMap|queryParamMap|uploadedFile|uploadedFiles|getParam|getParams|param|getBodyAsString|getBody|pathInfo|queryString|uri|url|contentType|userAgent|getFirst|asString)$/;
// What a request offers that is not text of the caller's.
const SAFE_REQUEST_MEMBER = /^(?:getMethod|getSession|getAttribute|getAttributeNames|getContextPath|getScheme|getServerName|getServerPort|getRemoteAddr|getRemoteHost|getLocale|getLocales|getProtocol|getRequestDispatcher|getServletContext|setAttribute|removeAttribute|isSecure|getCharacterEncoding|setCharacterEncoding|getContentLength|getUserPrincipal|isUserInRole|getDispatcherType|getAsyncContext|getLocalName|getLocalAddr|getLocalPort|getRemotePort|changeSessionId|login|logout|authenticate|getRequestedSessionId)$/;

export interface Chain {
  root: string;
  members: string[];
}

/** `request.getParameter("x")` -> root `request`, members `getParameter`. Undefined when the expression does not start from a name. */
export function chainOf(node: SyntaxNode): Chain | undefined {
  const members: string[] = [];
  let current: SyntaxNode | null = node;
  for (let steps = 0; current && steps < 64; steps++) {
    switch (current.type) {
      case "identifier":
        return { root: current.text, members: members.reverse() };
      case "method_invocation":
        members.push(current.childForFieldName("name")?.text ?? "");
        current = current.childForFieldName("object");
        break;
      case "field_access":
        members.push(current.childForFieldName("field")?.text ?? "");
        current = current.childForFieldName("object");
        break;
      case "array_access":
        current = current.childForFieldName("array");
        break;
      case "parenthesized_expression":
      case "cast_expression":
        current = current.childForFieldName("value") ?? current.namedChild(current.namedChildCount - 1);
        break;
      default:
        return undefined;
    }
  }
  return undefined;
}

/** A value the caller sent: `request.getParameter("q")`, `request.getHeader("X")`, `ctx.queryParam("id")`. */
export function isRequestSource(node: SyntaxNode, roots: Roots): boolean {
  if (node.type !== "method_invocation" && node.type !== "field_access" && node.type !== "array_access") return false;
  const chain = chainOf(node);
  if (!chain || chain.members.length === 0 || !roots.requests.has(chain.root)) return false;
  const first = chain.members[0] as string;
  return !SAFE_REQUEST_MEMBER.test(first) && (REQUEST_SOURCE.test(first) || node.type === "field_access");
}

/** The name of the method or constructed type, its receiver text and arguments, for a call or a `new`. */
export interface CallInfo {
  /** The method name (`executeQuery`), or the type (`File`) of a `new`. */
  name: string;
  /** `request`, `Runtime.getRuntime()`, `conn.createStatement()`; "" for an unqualified call or a `new`. */
  receiver: string;
  receiverNode: SyntaxNode | undefined;
  args: SyntaxNode[];
  isNew: boolean;
}

export function callInfo(call: SyntaxNode): CallInfo | undefined {
  if (call.type === "method_invocation") {
    const object = call.childForFieldName("object") ?? undefined;
    // `java.net.URLDecoder.decode(...)` is `URLDecoder.decode(...)`: a fully qualified class name loses its package
    const receiver = object?.text.replace(/\s+/g, "").replace(/^(?:[a-z_]\w*\.)+(?=[A-Z])/, "") ?? "";
    return { name: call.childForFieldName("name")?.text ?? "", receiver, receiverNode: object, args: argumentsOf(call), isNew: false };
  }
  if (call.type === "object_creation_expression") {
    return { name: call.childForFieldName("type")?.text.replace(/<.*>$/s, "").replace(/^.*\./, "") ?? "", receiver: "", receiverNode: undefined, args: argumentsOf(call), isNew: true };
  }
  return undefined;
}

export function argumentsOf(call: SyntaxNode): SyntaxNode[] {
  return (call.childForFieldName("arguments")?.namedChildren ?? []).filter((a) => a.type !== "line_comment" && a.type !== "block_comment");
}

const CLEANING_CALL =
  /^(?:Integer\.(?:parseInt|valueOf|parseUnsignedInt)|Long\.(?:parseLong|valueOf)|Short\.parseShort|Byte\.parseByte|Double\.(?:parseDouble|valueOf)|Float\.parseFloat|Boolean\.(?:parseBoolean|valueOf)|BigDecimal|BigInteger|UUID\.fromString|LocalDate\.parse|LocalDateTime\.parse|Instant\.parse|Objects\.hash|Character\.getNumericValue|StringEscapeUtils\.\w+|HtmlUtils\.\w+|Encode\.\w+|ESAPI\.\w+(?:\(\))?\.\w+|URLEncoder\.encode|UriUtils\.encode\w*|UriComponentsBuilder\.\w+|FilenameUtils\.(?:getName|getBaseName|getExtension)|FileNameUtils\.\w+|StringUtils\.(?:isBlank|isEmpty|isNumeric|length)|Jsoup\.clean|Sanitizers\.\w+|PolicyFactory\.sanitize|Pattern\.quote|Matcher\.quoteReplacement|DigestUtils\.\w+|Base64\.\w+\(\)\.encode\w*|Hex\.encode\w*|MessageDigest\.\w+|BCrypt\.\w+|escape\w*|sanitize\w*|validate\w*|isValid\w*|safe\w*)$/;
const CLEANING_METHOD = /^(?:length|size|isEmpty|isBlank|equals|equalsIgnoreCase|contains|startsWith|endsWith|matches|hashCode|compareTo|indexOf|lastIndexOf|intValue|longValue|doubleValue|booleanValue|ordinal|getFileName|getName|escapeHtml\w*|htmlEscape|sanitize\w*|encode\w*|isPresent|count|ifPresent)$/;
// Calls that give back (a form of) their arguments: the value is still the caller's.
const PASS_THROUGH_CALL =
  /^(?:String\.(?:valueOf|format|join|copyValueOf)|Objects\.(?:toString|requireNonNull|requireNonNullElse)|Optional\.(?:of|ofNullable)|Paths\.get|Path\.of|Files\.(?:readString|readAllLines|readAllBytes|newBufferedReader|newInputStream|lines|probeContentType)|Arrays\.(?:asList|toString|stream|copyOf)|List\.of|Set\.of|Map\.of|Collections\.(?:singletonList|singleton|unmodifiableList)|MessageFormat\.format|URI\.create|Path\.resolve|StringUtils\.(?:trim|strip|lowerCase|upperCase|replace|join|substring|defaultString|defaultIfBlank|defaultIfEmpty|capitalize|remove\w*|abbreviate)|FilenameUtils\.(?:concat|normalize|getFullPath)|Strings\.\w+|URLDecoder\.decode|Base64\.\w+\(\)\.decode|UriUtils\.decode|Base64\.(?:encodeBase64\w*|decodeBase64\w*|encode\w*|decode\w*)|Hex\.(?:encodeHex\w*|decodeHex)|StringEscapeUtils\.unescape\w+|HtmlUtils\.htmlUnescape)$/;
// Methods of a tainted receiver that give back text built from it (getters of a DTO included).
const PROPAGATING_METHOD =
  /^(?:get\w*|is\w+|to\w*|trim|strip\w*|lower\w*|upper\w*|replace\w*|substring|subSequence|concat|split|join|repeat|format\w*|orElse\w*|orElseThrow|map|filter|value|text|read\w*|next\w*|append|insert|toString|toLowerCase|toUpperCase|stream|collect|iterator|first|findFirst|findAny|values|entrySet|keySet|nextLine|lines|normalize|resolve\w*|decode\w*|unwrap|apply|call|name|as\w+)$/;
const BUILDING_METHOD = /^(?:append|insert|concat|replace\w*|join|format\w*|resolve\w*|add|put|set\w*|orElse|orElseGet|getOrDefault)$/;
// JSON / XML mapping: the result holds what the input held.
const MAPPING_METHOD = /^(?:readValue|readTree|fromJson|convertValue|treeToValue|parseObject|toObject|parseArray|unmarshal|deserialize|parse|fromXML|load)$/;
const PASS_THROUGH_NEW = /^(?:String|StringBuilder|StringBuffer|File|URL|URI|FileInputStream|FileReader|BufferedReader|InputStreamReader|ByteArrayInputStream|Scanner|StringReader|ArrayList|HashMap|LinkedHashMap|HashSet|LinkedList|Path|FileSystemResource|UrlResource|ClassPathResource|PathResource|HttpGet|HttpPost|HttpPut|HttpDelete|HttpHead|GenericUrl|RedirectView|ModelAndView|StringEntity|JSONObject|JSONArray|JsonParser|SimpleDateFormat)$/;

export function carriedBy(expression: SyntaxNode, tainted: ReadonlySet<string>, roots: Roots, ignorePaths = false): string | undefined {
  const stack: SyntaxNode[] = [expression];
  while (stack.length > 0) {
    const node = stack.pop() as SyntaxNode;
    checkBudget();
    switch (node.type) {
      case "identifier":
        if (tainted.has(node.text)) return node.text;
        break;
      case "field_access":
      case "array_access": {
        if (isRequestSource(node, roots) && !(ignorePaths && PATH_SOURCE.test(node.text))) return short(node.text);
        const base = node.childForFieldName("object") ?? node.childForFieldName("array");
        if (base) stack.push(base);
        break;
      }
      case "method_invocation": {
        if (isRequestSource(node, roots) && !(ignorePaths && PATH_SOURCE.test(node.text))) return short(node.text);
        const info = callInfo(node);
        if (!info) break;
        const full = info.receiver ? `${info.receiver}.${info.name}` : info.name;
        if (CLEANING_CALL.test(full)) break;
        // a method of this project: what it hands back is what the arguments it returns held
        const back = roots.returns?.(node);
        if (back) {
          for (const index of back) {
            const argument = info.args[index];
            if (argument) stack.push(argument);
          }
          break;
        }
        if (PASS_THROUGH_CALL.test(full)) {
          for (const a of info.args) stack.push(a);
          break;
        }
        if (info.receiverNode) {
          if (CLEANING_METHOD.test(info.name)) break;
          if (MAPPING_METHOD.test(info.name) && info.args[0]) {
            stack.push(info.args[0]);
            break;
          }
          if (PROPAGATING_METHOD.test(info.name)) {
            stack.push(info.receiverNode);
            if (BUILDING_METHOD.test(info.name)) for (const a of info.args) stack.push(a);
          }
        }
        break;
      }
      case "object_creation_expression": {
        const info = callInfo(node);
        if (info && PASS_THROUGH_NEW.test(info.name)) for (const a of info.args) stack.push(a);
        break;
      }
      case "binary_expression": {
        if (node.childForFieldName("operator")?.text === "+") {
          const left = node.childForFieldName("left");
          const right = node.childForFieldName("right");
          if (right) stack.push(right);
          if (left) stack.push(left);
        }
        break;
      }
      case "ternary_expression": {
        const yes = node.childForFieldName("consequence");
        const no = node.childForFieldName("alternative");
        if (no) stack.push(no);
        if (yes) stack.push(yes);
        break;
      }
      case "assignment_expression": {
        const right = node.childForFieldName("right");
        if (right) stack.push(right);
        break;
      }
      case "parenthesized_expression":
      case "cast_expression":
        stack.push(node.childForFieldName("value") ?? node.namedChild(node.namedChildCount - 1) ?? node);
        break;
      case "array_creation_expression":
      case "array_initializer":
      case "element_value_array_initializer":
        for (const child of node.namedChildren) if (child.type !== "type_identifier" && child.type !== "dimensions") stack.push(child);
        break;
      default:
        break;
    }
  }
  return undefined;
}

function short(text: string): string {
  return text.length > 60 ? `${text.slice(0, 57)}...` : text;
}

/** What the request line carries: it starts with "/", so it is a path, not a host (it cannot choose the server of an outgoing request). */
export const PATH_SOURCE = /getRequestURI|getPathInfo|getServletPath|getRequestURL|getQueryString|pathInfo|uri\(/;

/** Names an assignment target writes: `a`, `this.a` (the field), `a.b` (the object), `a[i]` (the array). */
export function targetName(target: SyntaxNode): string | undefined {
  switch (target.type) {
    case "identifier":
      return target.text;
    case "field_access": {
      const object = target.childForFieldName("object");
      // this.name = x -> name; a.name = x -> a
      return object?.type === "this" ? target.childForFieldName("field")?.text : object ? targetName(object) : undefined;
    }
    case "array_access": {
      const array = target.childForFieldName("array");
      return array ? targetName(array) : undefined;
    }
    case "parenthesized_expression":
      return target.namedChild(0) ? targetName(target.namedChild(0) as SyntaxNode) : undefined;
    default:
      return undefined;
  }
}

/** Walks a method's own statements, reporting events in the order they happen. Local and anonymous classes are other scopes; lambdas share the names. */
export interface WalkHandlers {
  enter?(node: SyntaxNode): void;
  exit?(node: SyntaxNode): void;
}

export function walkMethod(fn: SyntaxNode, handlers: WalkHandlers, skipLambda?: (lambda: SyntaxNode) => boolean): void {
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
    // a handler written inline (Spark `get("/x", (req, res) -> {...})`) is a method of its own and is looked at separately
    if (node.type === "lambda_expression" && skipLambda?.(node)) continue;
    if (node.type === "class_body" && node.parent?.type === "object_creation_expression") continue;
    handlers.enter?.(node);
    stack.push({ node, leaving: true });
    const children = node.namedChildren;
    for (let i = children.length - 1; i >= 0; i--) stack.push({ node: children[i] as SyntaxNode, leaving: false });
  }
}

/**
 * Runs `onCall` for every method call and `new` of the method, with the names that are the caller's AT THAT POINT (assignments and loops
 * update the set as the walk goes; a name assigned something clean is no longer tainted). `initial` names are tainted from the start (the
 * parameters of a helper that is being summarised, or of a handler that the framework fills).
 */
export function trackTaint(
  fn: SyntaxNode,
  roots: Roots,
  initial: ReadonlySet<string>,
  fileText: string,
  handlers: {
    /** `pathOnly`: the tainted names whose only source is the request line (a path, see PATH_SOURCE). */
    onCall?(call: SyntaxNode, tainted: ReadonlySet<string>, pathOnly: ReadonlySet<string>): void;
    onReturn?(statement: SyntaxNode, tainted: ReadonlySet<string>): void;
  },
): void {
  const tainted = new Set(initial);
  for (const name of roots.params) tainted.add(name);
  const pathOnly = new Set<string>();
  // An assignment in one branch (`case 'B': bar = "clean"`, `else { x = "" }`) does not undo the taint another branch gave the name: after the
  // branches the name may hold either, so a clean value only clears the name when the assignment is at the top level of the method.
  const conditional = (node: SyntaxNode): boolean => {
    for (let p: SyntaxNode | null = node.parent; p && p.id !== fn.id; p = p.parent) {
      if (/^(?:switch_block_statement_group|switch_rule|if_statement|while_statement|for_statement|enhanced_for_statement|do_statement|try_statement|catch_clause|finally_clause|ternary_expression|lambda_expression)$/.test(p.type)) return true;
    }
    return false;
  };
  // `if (!allowed.contains(x)) x = DEFAULT;`: a check that falls back to a clean value makes the name clean on both paths
  const fallback = (site: SyntaxNode, name: string): boolean => {
    const mention = new RegExp("\\b" + name + "\\b");
    for (let p: SyntaxNode | null = site.parent; p && p.id !== fn.id; p = p.parent) {
      if (p.type !== "if_statement") continue;
      const condition = p.childForFieldName("condition")?.text ?? "";
      if (mention.test(condition) && !/==\s*null|!=\s*null|isEmpty\(|isBlank\(|==\s*""|length\(\)\s*==\s*0/.test(condition)) return true;
    }
    return false;
  };
  const assign = (name: string | undefined, value: SyntaxNode | null, additive: boolean, site?: SyntaxNode): void => {
    if (!name || !value) return;
    const carries = carriedBy(value, tainted, roots) !== undefined;
    if (carries) {
      const beyondPath = new Set([...tainted].filter((n) => !pathOnly.has(n)));
      tainted.add(name);
      if (carriedBy(value, beyondPath, roots, true) === undefined) pathOnly.add(name);
      else pathOnly.delete(name);
    } else if (!additive && !(site && conditional(site) && !fallback(site, name))) {
      tainted.delete(name); // `x = clean`: no longer the caller's text
      pathOnly.delete(name);
    }
  };
  walkMethod(
    fn,
    {
      enter(node) {
        if (node.type === "enhanced_for_statement") {
          const value = node.childForFieldName("value");
          const name = node.childForFieldName("name")?.text;
          if (value && name && carriedBy(value, tainted, roots) !== undefined) tainted.add(name);
        }
      },
      exit(node) {
        switch (node.type) {
          case "variable_declarator":
            assign(node.childForFieldName("name")?.text, node.childForFieldName("value"), false, node);
            break;
          case "resource":
            assign(node.childForFieldName("name")?.text, node.childForFieldName("value"), false);
            break;
          case "assignment_expression": {
            const left = node.childForFieldName("left");
            const operator = node.childForFieldName("operator")?.text ?? "=";
            assign(left ? targetName(left) : undefined, node.childForFieldName("right"), operator !== "=", node);
            break;
          }
          case "method_invocation":
          case "object_creation_expression": {
            // sb.append(x), list.add(x), map.put(k, x): the container now holds the caller's text
            const info = callInfo(node);
            if (info && !info.isNew && info.receiverNode && /^(?:append|insert|add|addAll|put|putAll|offer|push|concat)$/.test(info.name)) {
              // sb.append(x) and the chain sb.append("a").append(x): the container at the start of the chain holds the text
              const holder = info.receiverNode.type === "identifier" ? info.receiverNode.text : /^(?:append|insert)$/.test(info.name) ? chainOf(info.receiverNode)?.root : undefined;
              if (holder && info.args.some((a) => carriedBy(a, tainted, roots) !== undefined)) tainted.add(holder);
            }
            handlers.onCall?.(node, tainted, pathOnly);
            break;
          }
          case "return_statement":
            handlers.onReturn?.(node, tainted);
            break;
          default:
            break;
        }
      },
    },
    (lambda) => hasRoots(rootsOf(lambda, fileText)),
  );
}
