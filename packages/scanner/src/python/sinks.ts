import { SyntaxNode } from "../parsers/utils";
import { Severity, VulnerabilityType } from "../types";
import { calleeText, callArguments } from "./engine";

/**
 * The dangerous calls of Python web code, and which of their arguments must not be the caller's. Each entry says how to find the
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

const HTTP_METHODS = "get|post|put|delete|patch|head|options|request|stream|send";
const SQL_CALL = /(?:^|\.)(?:execute|executemany|executescript|raw|extra|read_sql|read_sql_query|exec_driver_sql)$/;
const SQL_WRAPPER = /^(?:text|sa\.text|sqlalchemy\.text|RawSQL|sql\.SQL|SQL|literal_column)$/;
const SHELL_ALWAYS = /^(?:os\.system|os\.popen|os\.popen2|os\.popen3|subprocess\.getoutput|subprocess\.getstatusoutput|commands\.getoutput|commands\.getstatusoutput|asyncio\.create_subprocess_shell|pty\.spawn)$/;
const SUBPROCESS = /^subprocess\.(?:run|call|check_call|check_output|Popen)$|^Popen$/;
const CODE_CALL = /^(?:eval|exec|compile)$/;
const TEMPLATE_CALL = /^(?:render_template_string|jinja2\.Template|Template|Environment\(\)\.from_string|env\.from_string|jinja_env\.from_string|mako\.template\.Template)$|(?:^|\.)from_string$/;
const DESERIALIZE = /^(?:pickle\.loads?|cPickle\.loads?|_pickle\.loads?|marshal\.loads?|dill\.loads?|jsonpickle\.decode|shelve\.open|yaml\.unsafe_load|yaml\.full_load|yaml\.load|yaml\.load_all|torch\.load)$/;
const FILE_ARG0 = /^(?:open|io\.open|codecs\.open|send_file|flask\.send_file|FileResponse|os\.remove|os\.unlink|os\.rmdir|os\.removedirs|os\.listdir|os\.scandir|os\.makedirs|os\.mkdir|os\.chdir|shutil\.rmtree|os\.walk)$/;
const FILE_ARG01 = /^(?:shutil\.copy|shutil\.copy2|shutil\.copyfile|shutil\.copytree|shutil\.move|os\.rename|os\.replace|os\.symlink)$/;
const PATH_METHOD = /^(?:read_text|read_bytes|open|write_text|write_bytes|unlink|rmdir|iterdir|glob|rglob|touch|mkdir|rename|replace)$/;
const SSRF_CALL = new RegExp(`^(?:requests|httpx|urllib3|urllib\\.request|http\\.client|aiohttp)\\.(?:${HTTP_METHODS}|urlopen|Request|HTTPConnection|HTTPSConnection)$|^(?:urlopen|urllib\\.urlopen|urllib2\\.urlopen)$`);
const REDIRECT_CALL = /^(?:redirect|flask\.redirect|shortcuts\.redirect|HttpResponseRedirect|HttpResponsePermanentRedirect|RedirectResponse|redirect_to)$/;
const HTML_CALL = /^(?:HttpResponse|HTMLResponse|make_response|flask\.make_response|Markup|markupsafe\.Markup|flask\.Markup|mark_safe|safestring\.mark_safe|SafeString)$/;

// `https://api.example.com/users/` + id: the scheme and the whole host are written in the code, so the caller picks a path, not a server.
const FIXED_HOST = /^[rbfu]*["']https?:\/\/[A-Za-z0-9.-]+(?::\d+)?[/?#]/i;

function firstText(node: SyntaxNode | undefined): string {
  if (!node) return "";
  if (node.type === "binary_operator") return firstText(node.childForFieldName("left") ?? undefined);
  if (node.type === "call") {
    // "https://host/{}".format(x)
    const callee = node.childForFieldName("function");
    return callee?.type === "attribute" ? firstText(callee.childForFieldName("object") ?? undefined) : "";
  }
  return node.text;
}

// `redirect("/items/" + x)`, `redirect(f"{reverse('home')}?id={x}")`: the target starts with a path of this site, so the caller cannot change the host.
const SAME_SITE_PREFIX = /^[rbfu]*["'](?:\/(?![/\\])|\{\s*(?:reverse|reverse_lazy|url_for|resolve_url)\()/i;

function hasFixedHost(argument: SyntaxNode | undefined): boolean {
  return FIXED_HOST.test(firstText(argument));
}

function unwrapSql(argument: SyntaxNode): SyntaxNode {
  if (argument.type === "call") {
    const callee = argument.childForFieldName("function")?.text ?? "";
    if (SQL_WRAPPER.test(callee)) return argument.childForFieldName("arguments")?.namedChild(0) ?? argument;
  }
  return argument;
}

function truthy(node: SyntaxNode | undefined): boolean {
  return node?.text === "True" || node?.text === "1";
}

const SQL_MESSAGE = (via: string): string =>
  `User-controlled input ('${via}') flows into a SQL query without parameterization. Pass the values separately: ` +
  `cursor.execute("SELECT ... WHERE id = %s", (value,)) (SQLAlchemy: text("... :id"), {"id": value}; Django: Model.objects.filter(...) or raw(sql, [value])) instead of building the text with f-strings, % or +.`;

export function sinksOf(call: SyntaxNode, fileText: string): SinkSpec[] {
  const name = calleeText(call);
  if (!name) return [];
  const { positional, keywords } = callArguments(call);
  const specs: SinkSpec[] = [];
  const first = positional[0];

  if (SQL_CALL.test(name)) {
    const args = name.endsWith(".extra") ? [...positional, ...keywords.values()] : first ? [unwrapSql(first)] : [];
    specs.push({ rule: "sql-injection", severity: "critical", confidence: "medium", args, message: SQL_MESSAGE });
  }

  if (SHELL_ALWAYS.test(name) || (SUBPROCESS.test(name) && truthy(keywords.get("shell")))) {
    specs.push({
      rule: "command-injection",
      severity: "critical",
      confidence: "medium",
      args: first ? [first] : [],
      message: (via) =>
        `User-controlled input ('${via}') flows into a shell command. The string is run by a shell, so ; | && $( ) in it become commands. ` +
        `Pass a list of arguments without a shell (subprocess.run(["ls", path], check=True)) and validate the value.`,
    });
  }

  if (CODE_CALL.test(name)) {
    specs.push({
      rule: "code-injection",
      severity: "critical",
      confidence: "medium",
      args: first ? [first] : [],
      message: (via) => `User-controlled input ('${via}') is evaluated as Python code (${name}). Anyone who controls it runs commands on your server. Parse the value (json.loads, int(), ast.literal_eval) instead of evaluating it.`,
    });
  }

  if (TEMPLATE_CALL.test(name) && (/(?:^|\.)from_string$|render_template_string|jinja2\.Template|mako/.test(name) || /jinja2|django\.template|mako/.test(fileText))) {
    specs.push({
      rule: "code-injection",
      severity: "critical",
      confidence: "medium",
      args: first ? [first] : [],
      message: (via) =>
        `User-controlled input ('${via}') becomes the text of a template (${name}): server-side template injection, which lets a caller run Python code ` +
        `({{ ''.__class__... }}). Keep the template fixed and pass the value as a variable: render_template_string("Hello {{ name }}", name=value).`,
    });
  }

  if (DESERIALIZE.test(name)) {
    const loader = [...keywords.entries()].find(([k]) => k === "Loader")?.[1].text ?? positional[1]?.text ?? "";
    const isYamlLoad = /^yaml\.(?:load|load_all)$/.test(name);
    if (!isYamlLoad || !/Safe|BaseLoader/.test(loader)) {
      specs.push({
        rule: "insecure-deserialization",
        severity: "critical",
        confidence: "medium",
        args: first ? [first] : [],
        message: (via) =>
          `User-controlled input ('${via}') is deserialized with ${name}, which can run code while loading it. ` +
          `Use a data-only format (json.loads) or yaml.safe_load.`,
      });
    }
  }

  if (FILE_ARG0.test(name) || FILE_ARG01.test(name)) {
    const args = FILE_ARG01.test(name) ? positional.slice(0, 2) : first ? [first] : [];
    specs.push({
      rule: "path-traversal",
      severity: "high",
      confidence: "medium",
      args,
      message: (via) =>
        `User-controlled input ('${via}') is used to build a file path. ../ in it escapes the folder you meant (/etc/passwd, your .env). ` +
        `Use werkzeug.utils.secure_filename(name) or os.path.basename, join it to a fixed folder, and check that the resolved path is still inside it.`,
    });
  }

  const callee = call.childForFieldName("function");
  if (callee?.type === "attribute" && PATH_METHOD.test(callee.childForFieldName("attribute")?.text ?? "")) {
    const object = callee.childForFieldName("object");
    const objectCallee = object?.type === "call" ? (object.childForFieldName("function")?.text ?? "") : "";
    if (/^(?:pathlib\.)?(?:Path|PurePath)$/.test(objectCallee) && object) {
      const arg = object.childForFieldName("arguments")?.namedChild(0);
      if (arg) {
        specs.push({
          rule: "path-traversal",
          severity: "high",
          confidence: "medium",
          args: [arg],
          message: (via) => `User-controlled input ('${via}') is used to build a file path (Path(...).${callee.childForFieldName("attribute")?.text}()). ../ in it escapes the folder you meant. Reduce it to a file name and check the resolved path stays inside the folder.`,
        });
      }
    }
  }

  if (SSRF_CALL.test(name)) {
    const target = first ?? keywords.get("url");
    if (target && !hasFixedHost(target)) {
      specs.push({
        rule: "ssrf",
        severity: "high",
        confidence: "medium",
        args: [target],
        message: (via) =>
          `User-controlled input ('${via}') is used to build a URL that the server fetches. An attacker can point it at internal services ` +
          `(localhost, 169.254.169.254 cloud metadata, private IP ranges). Check the host against an allowlist and block private address ranges before the request.`,
      });
    }
  }

  if (REDIRECT_CALL.test(name)) {
    const target = first ?? keywords.get("url") ?? keywords.get("to");
    if (target && !SAME_SITE_PREFIX.test(firstText(target))) {
      specs.push({
        rule: "open-redirect",
        severity: "medium",
        confidence: "medium",
        args: [target],
        message: (via) =>
          `User-controlled input ('${via}') decides where the server redirects. An attacker sends a link on your domain that bounces victims to a phishing site. ` +
          `Redirect only to paths you build yourself, or check the target with url_has_allowed_host_and_scheme(target, allowed_hosts={request.get_host()}) (Django) / an allowlist first.`,
      });
    }
  }

  if (HTML_CALL.test(name) && first) {
    specs.push({
      rule: "xss",
      severity: "high",
      confidence: "medium",
      args: [first],
      message: (via) =>
        `User-controlled input ('${via}') is written into an HTML response (${name}) without escaping. A page that carries <script> in the value runs it in your visitors' browsers. ` +
        `Escape it (markupsafe.escape / django.utils.html.escape) or render it through a template, which escapes by default; never mark user input safe.`,
    });
  }
  return specs;
}

/** `return f"<p>{name}</p>"` in a handler: Flask sends a returned string as HTML. */
export const HTML_IN_STRING = /<\s*[A-Za-z!/]/;

export const XSS_RETURN_MESSAGE = (via: string): string =>
  `User-controlled input ('${via}') is returned inside an HTML string. Flask sends a returned string as HTML, so a value with <script> runs in your visitors' browsers. ` +
  `Escape it (markupsafe.escape(value)) or return render_template("page.html", value=value), which escapes by default.`;
