import { SyntaxNode } from "../parsers/utils";
import { Severity, VulnerabilityType } from "../types";
import { PATH_SOURCE, Roots, argumentsOf, callInfo, chainOf } from "./engine";

/**
 * The dangerous calls of Java web code, and which of their arguments must not be the caller's. Each entry says how to find the
 * arguments; the engine (engine.ts) says whether one of them carries the caller's value.
 */

export interface SinkSpec {
  rule: VulnerabilityType;
  severity: Severity;
  confidence: "high" | "medium" | "low";
  /** The arguments to check. */
  args: SyntaxNode[];
  message: (via: string) => string;
}

export function isStringLiteral(node: SyntaxNode | undefined): boolean {
  return node?.type === "string_literal" || node?.type === "text_block";
}

export function literalValue(node: SyntaxNode | undefined): string | undefined {
  if (!node) return undefined;
  if (node.type === "string_literal") return node.text.slice(1, -1);
  if (node.type === "text_block") return node.text.replace(/^"""\s*\n?/, "").replace(/"""$/, "");
  return undefined;
}

// `jdbcTemplate.query(...)`, `namedParameterJdbcTemplate.update(...)`: a template that takes SQL text.
const JDBC_TEMPLATE = /(?:^|[._])(?:jdbc\w*|\w*template|namedParameter\w*|sql\w*|db|dao|repo\w*|jdbi|handle)(?:\(\))?$/i;
const STATEMENT_RECEIVER = /(?:^|[._])(?:st|stmt|statement|s|ps|conn|connection|con|db|jdbc\w*|\w*template|session|em|entityManager|dao|repo\w*|sql\w*|handle|dsl|create)(?:\(\))?$|createStatement\(\)$|getConnection\(\)$|\.prepareStatement\(/i;
const SQL_WORDS = /\b(?:select|insert\s+into|update|delete\s+from|where|order\s+by|group\s+by|having|union|drop|create\s+table|alter\s+table)\b/i;

const FILE_NEW = /^(?:File|FileInputStream|FileOutputStream|FileReader|FileWriter|RandomAccessFile|FileSystemResource|PathResource|FileSystemUrlResource|ZipFile)$/;
const FILES_METHOD = /^(?:readAllBytes|readAllLines|readString|write|writeString|newInputStream|newOutputStream|newBufferedReader|newBufferedWriter|copy|move|delete|deleteIfExists|lines|walk|list|createFile|createDirectories|createDirectory|exists|isDirectory|size|probeContentType|createTempFile)$/;

// restTemplate.getForObject(url, ...): a client that takes a URL. redisTemplate.delete(key), jdbcTemplate.update(sql) are other templates.
const REST_RECEIVER = /(?:rest\w*|\w*template|client|http\w*|webClient|api)$/i;
const NOT_HTTP_TEMPLATE = /redis|jdbc|jms|kafka|amqp|rabbit|mongo|jpa|hibernate|ldap|cassandra|elastic|neo4j|batch|transaction|sql|cache|stringRedis/i;
const HTTP_TEMPLATE_METHOD = /^(?:getForObject|getForEntity|postForObject|postForEntity|postForLocation|exchange|execute|put|delete|headForHeaders|optionsForAllow|retrieve)$/;

export const SQL_MESSAGE = (via: string): string =>
  `User-controlled input ('${via}') flows into a SQL query without parameterization. Pass the values separately: ` +
  `PreparedStatement ps = conn.prepareStatement("SELECT ... WHERE name = ?"); ps.setString(1, value); (JdbcTemplate: jdbc.query("... ?", mapper, value); JPA: a named parameter with setParameter) instead of building the text with +, String.format or StringBuilder.`;

export const XSS_MESSAGE = (via: string): string =>
  `User-controlled input ('${via}') is written into the HTTP response as it is. The browser treats it as HTML, and a value with <script> then runs in your visitors' browsers. ` +
  `Escape it for HTML (HtmlUtils.htmlEscape(value), Encode.forHtml from the OWASP Java Encoder), render pages through a template engine that escapes by default (Thymeleaf th:text), and set a JSON content type for API replies.`;

/**
 * The text a URL expression starts with, as far as the code spells it out, and the first piece it does not (a variable, a call).
 * `"https://api.example.com/users/" + id` -> text `https://api.example.com/users/`, rest `id`;
 * `String.format("%s://%s%s", "http", "0.0.0.0", uri)` -> text `http://0.0.0.0`, rest `uri`.
 */
export function urlPrefix(node: SyntaxNode | undefined): { text: string; rest: SyntaxNode | undefined } {
  if (!node) return { text: "", rest: undefined };
  if (isStringLiteral(node)) return { text: literalValue(node) ?? "", rest: undefined };
  if (node.type === "parenthesized_expression") return urlPrefix(node.namedChild(0) ?? undefined);
  if (node.type === "binary_expression" && node.childForFieldName("operator")?.text === "+") {
    const left = urlPrefix(node.childForFieldName("left") ?? undefined);
    if (left.rest) return left;
    const right = urlPrefix(node.childForFieldName("right") ?? undefined);
    return { text: left.text + right.text, rest: right.rest };
  }
  if (node.type === "method_invocation" && node.childForFieldName("object")?.text === "String" && node.childForFieldName("name")?.text === "format") {
    const args = argumentsOf(node);
    const format = literalValue(args[0]);
    if (format === undefined) return { text: "", rest: node };
    let text = "";
    let next = 1;
    for (let i = 0; i < format.length; i++) {
      if (format[i] !== "%") {
        text += format[i];
        continue;
      }
      const verb = /^%(?:\d+\$)?[-+# 0-9.]*([a-zA-Z%])/.exec(format.slice(i));
      if (!verb) return { text, rest: node };
      i += verb[0].length - 1;
      if (verb[1] === "%" || verb[1] === "n") {
        text += verb[1] === "n" ? "\n" : "%";
        continue;
      }
      const arg = args[next++];
      if (!arg) return { text, rest: undefined };
      const value = isStringLiteral(arg) ? literalValue(arg) : undefined;
      if (value === undefined) return { text, rest: arg };
      text += value;
    }
    return { text, rest: undefined };
  }
  return { text: "", rest: node };
}

const CONFIGURED_HOST = /^(?:\w+\.)*(?:base_?url|site_?url|frontend_?url|app_?url|public_?url|host_?url|api_?url|server_?url|\w*endpoint)\w*/i;

/** The URL's first piece, when the caller may choose the server (`next`, `"https://" + host`); nothing when the code fixes the host. */
function redirectTarget(argument: SyntaxNode | undefined, prefix = ""): SyntaxNode[] {
  const { text: full, rest } = urlPrefix(argument);
  const text = prefix && full.startsWith(prefix) ? full.slice(prefix.length) : full;
  if (!rest) return [];
  const open = text === "" || /^(?:[A-Za-z][A-Za-z0-9+.-]*:)?(?:\/\/[^/?#]*)?$/.test(text);
  return open ? [rest] : [];
}

/** True when the code fixes the server of an outgoing request (the caller can only choose a path or a query). */
function hasFixedHost(argument: SyntaxNode | undefined): boolean {
  const { text, rest } = urlPrefix(argument);
  if (/^(?:https?:)?\/\/[A-Za-z0-9.-]+(?::\d+)?[/?#]/i.test(text)) return true;
  if (/^https?:\/\/[A-Za-z0-9.-]+(?::\d+)?$/i.test(text) && rest && PATH_SOURCE.test(rest.text)) return true;
  return text === "" && !!rest && CONFIGURED_HOST.test(rest.text);
}

export function sinksOf(call: SyntaxNode, roots: Roots, fnText: string): SinkSpec[] {
  const info = callInfo(call);
  if (!info || !info.name) return [];
  const { name, receiver, args, isNew } = info;
  const first = args[0];
  const full = receiver ? `${receiver}.${name}` : name;
  const specs: SinkSpec[] = [];

  // SQL: statement.executeQuery(sql), conn.prepareStatement(sql), jdbc.queryForList(sql), em.createNativeQuery(sql)
  if (!isNew && first) {
    const looksSql = SQL_WORDS.test(first.text);
    let sql: SyntaxNode | undefined;
    if (/^(?:executeQuery|executeUpdate|execute|executeLargeUpdate|addBatch|executeBatch)$/.test(name)) {
      if (STATEMENT_RECEIVER.test(receiver) || looksSql) sql = first;
    } else if (/^(?:prepareStatement|prepareCall|nativeSQL)$/.test(name)) {
      sql = first;
    } else if (/^(?:createQuery|createNativeQuery|createSQLQuery|createSqlQuery)$/.test(name)) {
      sql = first;
    } else if (/^(?:query|queryForObject|queryForList|queryForMap|queryForRowSet|queryForStream|update|batchUpdate|execute|queryForInt|queryForLong)$/.test(name) && JDBC_TEMPLATE.test(receiver) && (looksSql || first.type !== "string_literal")) {
      sql = first;
    } else if (/^(?:fetch|execute|query|select|resultQuery|fetchOne|fetchAny|fetchMap|fetchGroups)$/.test(name) && /(?:dsl|create|ctx)$/i.test(receiver) && looksSql) {
      sql = first;
    } else if (/^(?:createQuery|createUpdate|select|createNativeQuery)$/.test(name) && /(?:handle|jdbi|h)$/.test(receiver)) {
      sql = first;
    }
    if (sql) specs.push({ rule: "sql-injection", severity: "critical", confidence: "medium", args: [sql], message: SQL_MESSAGE });
  }

  // OS commands: Runtime.getRuntime().exec(cmd), new ProcessBuilder("sh", "-c", x)
  if ((name === "exec" && (/Runtime\.getRuntime\(\)$|^(?:rt|runtime)$/i.test(receiver) || (/^\w+$/.test(receiver) && new RegExp("\\b" + receiver + "\\s*=\\s*(?:java\\.lang\\.)?Runtime\\.getRuntime\\(\\)").test(fnText)))) || (isNew && name === "ProcessBuilder") || (name === "command" && args.length > 0 && /^(?:pb|\w*[Bb]uilder|\w*[Pp]rocess\w*)$/.test(receiver))) {
    const strings = args.flatMap((a) => (a.type === "array_creation_expression" ? (a.namedChildren.find((c) => c.type === "array_initializer")?.namedChildren ?? [a]) : [a]));
    const program = strings[0];
    const shell = /^"(?:sh|bash|zsh|dash|\/bin\/(?:ba|z|da)?sh|cmd|cmd\.exe|powershell|pwsh)"$/i.test(program?.text ?? "");
    const flag = strings.findIndex((a) => /^"(?:-c|-lc|\/c|\/k|-Command)"$/.test(a.text));
    const message = (via: string): string =>
      `User-controlled input ('${via}') flows into an OS command. ${shell ? "The string is run by a shell, so ; | && $( ) in it become commands." : "The caller chooses what runs or adds arguments to it."} ` +
      `Run a fixed program with each value as its own argument (new ProcessBuilder("convert", "--", input, output)), without a shell, and validate the value against an allow-list first.`;
    if (!isNew && args.length === 1 && program && program.type !== "array_creation_expression" && !isStringLiteral(program)) {
      // exec("ping " + host): one string, split on spaces: the value adds arguments (and a program, when it comes first)
      specs.push({ rule: "command-injection", severity: "critical", confidence: "medium", args: [program], message });
    } else if (shell && flag !== -1) {
      specs.push({ rule: "command-injection", severity: "critical", confidence: "medium", args: strings.slice(flag + 1), message });
    } else if (program && !isStringLiteral(program)) {
      specs.push({ rule: "command-injection", severity: "critical", confidence: "medium", args: [program], message });
    }
  }

  // Files
  const pathMessage = (via: string): string =>
    `User-controlled input ('${via}') is used as a file path. A value like ../../etc/passwd climbs out of the intended folder and reads or writes any file the server can reach. ` +
    `Take only the file name (FilenameUtils.getName / Paths.get(value).getFileName()), resolve it against a fixed folder, and check that the normalized result still starts with that folder (path.normalize().startsWith(base)).`;
  if (isNew && FILE_NEW.test(name) && first && !(first.type === "object_creation_expression" && FILE_NEW.test(callInfo(first)?.name ?? ""))) {
    // new File(parent, child): the child is the part that matters
    specs.push({ rule: "path-traversal", severity: "high", confidence: "medium", args: args.length >= 2 && name === "File" ? args.slice(0, 2) : [first], message: pathMessage });
  }
  // (a Path built by Paths.get(x) is a finding only when it is opened: the Path value carries the taint on to the Files call)
  if (!isNew && /^Files$/.test(receiver) && FILES_METHOD.test(name) && first) specs.push({ rule: "path-traversal", severity: "high", confidence: "medium", args: [first], message: pathMessage });
  if (!isNew && /^(?:getResourceAsStream|getRealPath|getResource|getRequestDispatcher|getResources)$/.test(name) && first) {
    specs.push({ rule: "path-traversal", severity: "high", confidence: "medium", args: [first], message: pathMessage });
  }
  if (!isNew && /^(?:transferTo)$/.test(name) && first) specs.push({ rule: "path-traversal", severity: "high", confidence: "medium", args: [first], message: pathMessage });
  if (!isNew && /^(?:getFile|getURL|getInputStream)$/.test(name) && /^(?:ResourceUtils|resourceLoader|loader|resolver)$/i.test(receiver) && first) {
    specs.push({ rule: "path-traversal", severity: "high", confidence: "medium", args: [first], message: pathMessage });
  }

  // Outgoing requests
  const ssrfMessage = (via: string): string =>
    `User-controlled input ('${via}') decides which URL the server requests. An attacker can point it at internal services, cloud metadata (169.254.169.254) or localhost. ` +
    `Allow only known hosts (compare the parsed URI's getHost() against an allow-list), refuse private addresses, and do not follow redirects blindly.`;
  let ssrfTarget: SyntaxNode | undefined;
  if (isNew && /^(?:URL|HttpGet|HttpPost|HttpPut|HttpDelete|HttpHead|HttpPatch|GenericUrl)$/.test(name)) ssrfTarget = first;
  else if (isNew && name === "URI" && first && /openConnection|openStream|HttpClient|HttpRequest|RestTemplate|\.send\(/.test(fnText)) ssrfTarget = first;
  else if (!isNew && /^(?:URI\.create|Jsoup\.connect|HttpRequest\.newBuilder|WebClient\.create|RestClient\.create)$/.test(full)) ssrfTarget = first;
  else if (!isNew && HTTP_TEMPLATE_METHOD.test(name) && REST_RECEIVER.test(receiver) && !NOT_HTTP_TEMPLATE.test(receiver) && (!/^(?:execute|put|delete|retrieve)$/.test(name) || /rest|http|web/i.test(receiver))) ssrfTarget = first;
  else if (!isNew && name === "uri" && /(?:get|post|put|delete|patch|head)\(\)$|webClient|client/i.test(receiver)) ssrfTarget = first;
  else if (!isNew && name === "url" && /Request\.Builder|Builder\(\)$|builder$/i.test(receiver)) ssrfTarget = first;
  if (ssrfTarget && !isNew && name === "URI.create") ssrfTarget = first;
  if (ssrfTarget && !hasFixedHost(ssrfTarget)) specs.push({ rule: "ssrf", severity: "high", confidence: "medium", args: [ssrfTarget], message: ssrfMessage });
  // new URL(x) alone is also how redirects and links are built: it is a finding only in a method that opens a connection
  const urlIndex = specs.findIndex((s) => s.rule === "ssrf");
  if (urlIndex !== -1 && isNew && name === "URL" && !/openConnection|openStream|getContent|HttpURLConnection/.test(fnText)) specs.splice(urlIndex, 1);

  // Redirects
  const redirectMessage = (via: string): string =>
    `User-controlled input ('${via}') decides where the visitor is sent. A link on your site can then lead to a look-alike page that asks for the password. ` +
    `Redirect only to a path of this site (it starts with a single "/", not "//"), or compare the parsed host against an allow-list.`;
  if (!isNew && name === "sendRedirect" && first) {
    const target = redirectTarget(first);
    if (target.length > 0) specs.push({ rule: "open-redirect", severity: "medium", confidence: "medium", args: target, message: redirectMessage });
  }
  if (isNew && /^(?:RedirectView|ModelAndView)$/.test(name) && first && (name === "RedirectView" || urlPrefix(first).text.startsWith("redirect:"))) {
    const target = redirectTarget(first, name === "ModelAndView" ? "redirect:" : "");
    if (target.length > 0) specs.push({ rule: "open-redirect", severity: "medium", confidence: "medium", args: target, message: redirectMessage });
  }
  if (!isNew && /^(?:setHeader|addHeader|header)$/.test(name) && /^"Location"$/i.test(first?.text ?? "") && args[1]) {
    const target = redirectTarget(args[1]);
    if (target.length > 0) specs.push({ rule: "open-redirect", severity: "medium", confidence: "medium", args: target, message: redirectMessage });
  }

  // CORS: the Origin header copied into Access-Control-Allow-Origin
  if (!isNew && /^(?:setHeader|addHeader|header)$/.test(name) && /^"Access-Control-Allow-Origin"$/i.test(first?.text ?? "") && args[1]) {
    specs.push({
      rule: "insecure-cors",
      severity: "high",
      confidence: "medium",
      args: [args[1]],
      message: (via) =>
        `The request's own value ('${via}') is copied into Access-Control-Allow-Origin. Every website is then allowed to read this API with the visitor's cookies. ` +
        `Compare the origin against a fixed allow-list and send back only an entry of it.`,
    });
  }

  // HTML written into the response
  if (!isNew && /^(?:print|println|write|printf|format|append|sendError)$/.test(name) && args.length > 0) {
    const chain = chainOf(call.childForFieldName("object") ?? call);
    const onWriter = roots.writers.has(receiver) || /\.(?:getWriter|getOutputStream)\(\)$/.test(receiver) || (!!chain && roots.responses.has(chain.root) && /getWriter|getOutputStream/.test(chain.members.join(".")));
    if (onWriter) specs.push({ rule: "xss", severity: "high", confidence: "medium", args: name === "sendError" ? args.slice(1) : args, message: XSS_MESSAGE });
  }
  if (!isNew && /^(?:html|result|send|render)$/.test(name) && roots.requests.size > 0 && /^(?:ctx|context|res|response|rc)$/.test(receiver) && first && /^(?:html)$/.test(name)) {
    specs.push({ rule: "xss", severity: "high", confidence: "medium", args: [first], message: XSS_MESSAGE });
  }

  // Deserialization, expression languages, scripts
  if (isNew && /^(?:ObjectInputStream|XMLDecoder)$/.test(name) && first) {
    specs.push({
      rule: "insecure-deserialization",
      severity: "critical",
      confidence: "medium",
      args: [first],
      message: (via) =>
        `Data from the caller ('${via}') is deserialized with ${name}. Java deserialization runs code chosen by whoever built the bytes (gadget chains in common libraries give remote code execution). ` +
        `Do not deserialize untrusted data: use JSON with a fixed target type (Jackson without default typing), or an ObjectInputFilter allow-list.`,
    });
  }
  if (!isNew && /^(?:load|loadAs|loadAll)$/.test(name) && /(?:yaml|snake\w*)$|newYaml\(\)$/i.test(receiver) && first) {
    specs.push({
      rule: "insecure-deserialization",
      severity: "critical",
      confidence: "medium",
      args: [first],
      message: (via) => `Data from the caller ('${via}') is parsed by SnakeYAML's default Yaml(), which instantiates any class named in the document (remote code execution). Use new Yaml(new SafeConstructor(new LoaderOptions())).`,
    });
  }
  if (!isNew && name === "fromXML" && first) {
    specs.push({ rule: "insecure-deserialization", severity: "critical", confidence: "medium", args: [first], message: (via) => `Data from the caller ('${via}') is turned into objects by XStream, which can instantiate any class. Configure an allow-list (xstream.allowTypes(...)) or use a fixed-schema format.` });
  }
  if (!isNew && /^(?:parseExpression|getValue|setValue|eval|evaluate|executeScript|runScript|compile)$/.test(name) && first) {
    const expression = /(?:parser|spel|expression|expr|engine|script\w*|shell|groovy\w*|ognl|mvel|interpreter)$/i.test(receiver) || /^(?:Ognl|MVEL|Eval)$/i.test(receiver) || /SpelExpressionParser|GroovyShell|ScriptEngine/.test(receiver);
    if (expression) {
      specs.push({
        rule: "code-injection",
        severity: "critical",
        confidence: "medium",
        args: [first],
        message: (via) =>
          `User-controlled input ('${via}') is evaluated as code (an expression language or a script engine). Spring's SpEL, OGNL, MVEL and Groovy can call any method: this is remote code execution. ` +
          `Do not evaluate request text; map it onto fixed operations. If an expression is needed, use a sandbox (SimpleEvaluationContext for SpEL).`,
      });
    }
  }
  if (!isNew && /^(?:forName|loadClass)$/.test(name) && first && /^(?:Class|classLoader|loader|\w*ClassLoader\(\)|Thread\.currentThread\(\)\.getContextClassLoader\(\))$/i.test(receiver)) {
    specs.push({
      rule: "code-injection",
      severity: "high",
      confidence: "low",
      args: [first],
      message: (via) => `User-controlled input ('${via}') chooses which class is loaded. The caller can pick any class on the classpath (and static initializers run on load). Map the value to a fixed list of classes.`,
    });
  }
  if (!isNew && /^(?:parse|process|evaluate)$/.test(name) && first && /^(?:Velocity|velocityEngine|engine|ve)$/i.test(receiver) && /StringReader/.test(first.text)) {
    specs.push({ rule: "code-injection", severity: "high", confidence: "low", args: [first], message: (via) => `User-controlled input ('${via}') becomes the template itself. Template directives in it can call methods of the objects you expose. Keep templates in files you wrote and pass the value as data.` });
  }

  return specs;
}

export { redirectTarget };
