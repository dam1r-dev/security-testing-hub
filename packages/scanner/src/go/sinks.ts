import { SyntaxNode } from "../parsers/utils";
import { Severity, VulnerabilityType } from "../types";
import { Roots, calleeText, callArguments, chainOf } from "./engine";

/**
 * The dangerous calls of Go web code, and which of their arguments must not be the caller's. Each entry says how to find the
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

// `db.Query`, `s.db.QueryRow`, `tx.Exec`, `h.Store.DB`: a database handle (a name is not enough for `.Get(...)`, which is everywhere).
const DB_RECEIVER = /(?:^|[._])(?:db|dbx|tx|conn|connection|pool|database|sqldb|gormdb|dao|repo|repository|queries|sqlx|orm|session)(?:\(\))?$/i;
const GORM_CHAIN = /\.(?:Model|Table|Where|Preload|Debug|Session|Joins|Select|Order|Limit|Scopes|Unscoped)\(/;
const SQL_WORDS = /\b(?:select|insert\s+into|update|delete\s+from|where|order\s+by|group\s+by|having|union|drop|create\s+table|alter\s+table)\b/i;

// the position of the SQL text among the arguments
const SQL_ARGUMENT: Record<string, number> = {
  Query: 0, QueryRow: 0, Exec: 0, Prepare: 0, Queryx: 0, QueryRowx: 0, NamedQuery: 0, NamedExec: 0, MustExec: 0, Raw: 0,
  QueryContext: 1, ExecContext: 1, QueryRowContext: 1, PrepareContext: 1, QueryxContext: 1, NamedQueryContext: 1, NamedExecContext: 1,
  Get: 1, Select: 1, GetContext: 2, SelectContext: 2,
  Where: 0, Having: 0, Order: 0, Group: 0, Joins: 0, Pluck: 0,
};
const GORM_ONLY = new Set(["Where", "Having", "Order", "Group", "Joins", "Pluck", "Raw"]);
const SQLX_ONLY = new Set(["Get", "Select", "GetContext", "SelectContext"]);

const FILE_ARG0 = /^(?:os\.(?:Open|OpenFile|ReadFile|WriteFile|Create|Remove|RemoveAll|Mkdir|MkdirAll|Stat|Lstat|ReadDir|Chdir|Truncate|Chmod|Chown|Chtimes|Readlink|DirFS)|ioutil\.(?:ReadFile|WriteFile|ReadDir)|filepath\.(?:Walk|WalkDir|Glob)|afero\.\w+|fs\.\w+\.Open|zip\.OpenReader|ini\.Load|viper\.SetConfigFile|template\.ParseFiles|template\.ParseGlob|tmpl\.ParseFiles|os\.NewFile)$/;
const FILE_ARG01 = /^(?:os\.(?:Rename|Symlink|Link))$/;
const HTTP_FUNCTION = /^(?:http\.(?:Get|Post|Head|PostForm)|http\.DefaultClient\.(?:Get|Post|Head|PostForm)|resty\.New\(\)\.R\(\)\.(?:Get|Post|Put|Delete|Head)|grequests\.\w+|fasthttp\.(?:Get|Post)Timeout|fasthttp\.(?:Get|Post))$/;
const HTTP_CLIENT_METHOD = /^(?:Get|Post|Head|PostForm|Put|Delete|Patch)$/;
const HTTP_CLIENT_RECEIVER = /(?:^|[._])(?:client|httpclient|http|cli|hc|resty|requester|fetcher|netclient)(?:\(\))?$|\.R\(\)$|http\.Client\{/i;

const CONFIGURED_HOST = /^(?:\w+\.)*(?:base_?url|site_?url|frontend_?url|app_?url|public_?url|host_?url)\w*/i;
// a value from the request line starts with "/": it is a path, so after a fixed host it cannot change the host
const PATH_SOURCE = /RequestURI|URL\.Path|EscapedPath|RawPath|URL\.RawQuery/;

/**
 * The text a URL expression starts with, as far as the code spells it out, and the first piece it does not (a variable, a call).
 * `"https://api.example.com/users/" + id` -> text `https://api.example.com/users/`, rest `id`;
 * `fmt.Sprintf("%s://%s%s", "http", "0.0.0.0", r.RequestURI)` -> text `http://0.0.0.0`, rest `r.RequestURI`.
 * Who controls the START of a URL decides which server it means.
 */
function urlPrefix(node: SyntaxNode | undefined): { text: string; rest: SyntaxNode | undefined } {
  if (!node) return { text: "", rest: undefined };
  if (isStringLiteral(node)) return { text: literalValue(node) ?? "", rest: undefined };
  if (node.type === "parenthesized_expression") return urlPrefix(node.namedChild(0) ?? undefined);
  if (node.type === "binary_expression" && node.childForFieldName("operator")?.text === "+") {
    const left = urlPrefix(node.childForFieldName("left") ?? undefined);
    if (left.rest) return left;
    const right = urlPrefix(node.childForFieldName("right") ?? undefined);
    return { text: left.text + right.text, rest: right.rest };
  }
  if (node.type === "call_expression" && node.childForFieldName("function")?.text === "fmt.Sprintf") {
    const args = callArguments(node);
    const format = literalValue(args[0]);
    if (format === undefined) return { text: "", rest: node };
    let text = "";
    let next = 1;
    for (let i = 0; i < format.length; i++) {
      if (format[i] !== "%") {
        text += format[i];
        continue;
      }
      const verb = /^%[-+# 0-9.*]*([a-zA-Z%])/.exec(format.slice(i));
      if (!verb) return { text, rest: node };
      i += verb[0].length - 1;
      if (verb[1] === "%") {
        text += "%";
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

/** The URL's first piece, when the caller may choose the server (`next`, `"https://" + host`); nothing when the code fixes the host. */
function redirectTarget(argument: SyntaxNode | undefined): SyntaxNode[] {
  const { text, rest } = urlPrefix(argument);
  if (!rest) return [];
  // `"/items/" + id`, `"https://example.com/x?" + q`, `"login?next=" + q`: the start is written in the code
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

function isStringLiteral(node: SyntaxNode | undefined): boolean {
  return node?.type === "interpreted_string_literal" || node?.type === "raw_string_literal";
}

function literalValue(node: SyntaxNode | undefined): string | undefined {
  if (!node || !isStringLiteral(node)) return undefined;
  return node.text.slice(1, -1);
}

const SQL_MESSAGE = (via: string): string =>
  `User-controlled input ('${via}') flows into a SQL query without parameterization. Pass the values separately: ` +
  `db.Query("SELECT ... WHERE id = $1", value) (MySQL: ?; GORM: db.Where("name = ?", value)) instead of building the text with +, fmt.Sprintf or string concatenation.`;

/** The text names of the calls that write into the response (`fmt.Fprintf(w, ...)`, `io.WriteString(w, ...)`, `w.Write(...)`). */
function writesToResponse(name: string, first: SyntaxNode | undefined, roots: Roots): boolean {
  if (!/^(?:fmt\.Fprint|fmt\.Fprintf|fmt\.Fprintln|io\.WriteString)$/.test(name)) return false;
  if (!first) return false;
  if (roots.writers.has(first.text)) return true;
  const chain = chainOf(first);
  return !!chain && roots.contexts.has(chain.root) && chain.members[0] === "Writer";
}

export const XSS_MESSAGE = (via: string): string =>
  `User-controlled input ('${via}') is written into the HTTP response as it is. The browser may treat it as HTML, and a value with <script> then runs in your visitors' browsers. ` +
  `Render it through html/template (it escapes by context), or escape it with html.EscapeString; for an API reply set the Content-Type to application/json and encode with json.NewEncoder.`;

export function sinksOf(call: SyntaxNode, roots: Roots): SinkSpec[] {
  const name = calleeText(call);
  if (!name) return [];
  const args = callArguments(call);
  const first = args[0];
  const specs: SinkSpec[] = [];
  const dot = name.lastIndexOf(".");
  const method = dot === -1 ? name : name.slice(dot + 1);
  const receiver = dot === -1 ? "" : name.slice(0, dot);
  const receiverText = call.childForFieldName("function")?.childForFieldName("operand")?.text.replace(/\s+/g, "") ?? receiver;

  // SQL
  if (dot !== -1 && method in SQL_ARGUMENT) {
    const index = SQL_ARGUMENT[method] as number;
    const sql = args[index];
    const dbLike = DB_RECEIVER.test(receiverText);
    const gormLike = GORM_CHAIN.test(receiverText);
    const sqlText = sql ? sql.text : "";
    const looksSql = SQL_WORDS.test(sqlText);
    const allowed = SQLX_ONLY.has(method) ? dbLike : GORM_ONLY.has(method) ? dbLike || gormLike : dbLike || looksSql;
    if (sql && allowed) specs.push({ rule: "sql-injection", severity: "critical", confidence: "medium", args: [sql], message: SQL_MESSAGE });
  }

  // OS commands: exec.Command("sh", "-c", x), exec.Command(x)
  if (/^exec\.(?:Command|CommandContext)$/.test(name) || /^(?:syscall\.Exec|os\.StartProcess)$/.test(name)) {
    const offset = name === "exec.CommandContext" ? 1 : 0;
    const program = args[offset];
    const rest = args.slice(offset + 1);
    const shell = /^["`](?:sh|bash|zsh|dash|ash|\/bin\/(?:ba|z|da)?sh|cmd|cmd\.exe|powershell|pwsh|powershell\.exe)["`]$/i.test(program?.text ?? "");
    const flag = rest.findIndex((a) => /^["`](?:-c|-lc|\/c|\/k|-Command|-command)["`]$/.test(a.text));
    const message = (via: string): string =>
      `User-controlled input ('${via}') flows into an OS command. ${shell ? "The string is run by a shell, so ; | && $( ) in it become commands." : "The caller chooses which program runs."} ` +
      `Run a fixed program with the value as one separate argument (exec.Command("ls", "-l", "--", path)), without a shell, and validate the value against an allow-list.`;
    if (program && shell && flag !== -1) specs.push({ rule: "command-injection", severity: "critical", confidence: "medium", args: rest.slice(flag + 1), message });
    else if (program && !shell && !isStringLiteral(program)) specs.push({ rule: "command-injection", severity: "critical", confidence: "medium", args: [program], message });
  }

  // Files
  const pathMessage = (via: string): string =>
    `User-controlled input ('${via}') is used as a file path. A value like ../../etc/passwd climbs out of the intended folder and reads or writes any file the server can reach. ` +
    `Take only the file name (filepath.Base), or join it to the base folder and check the result stays inside it (strings.HasPrefix(filepath.Clean(full), base)), or use os.OpenRoot / a fixed allow-list.`;
  if (FILE_ARG0.test(name) && first) specs.push({ rule: "path-traversal", severity: "high", confidence: "medium", args: [first], message: pathMessage });
  if (FILE_ARG01.test(name)) specs.push({ rule: "path-traversal", severity: "high", confidence: "medium", args: args.slice(0, 2), message: pathMessage });
  if (name === "http.ServeFile" && args[2]) specs.push({ rule: "path-traversal", severity: "high", confidence: "medium", args: [args[2]], message: pathMessage });
  if (name === "http.Dir" && first) specs.push({ rule: "path-traversal", severity: "medium", confidence: "low", args: [first], message: pathMessage });
  if (dot !== -1 && /^(?:File|FileAttachment|SendFile|Download|Attachment|Inline|SaveUploadedFile|SaveFile|FileFromFS)$/.test(method)) {
    const chain = chainOf(call.childForFieldName("function") as SyntaxNode);
    if (chain && roots.contexts.has(chain.root)) {
      const target = method === "SaveUploadedFile" || method === "SaveFile" ? args[1] : first;
      if (target) specs.push({ rule: "path-traversal", severity: "high", confidence: "medium", args: [target], message: pathMessage });
    }
  }

  // Outgoing requests
  const ssrfMessage = (via: string): string =>
    `User-controlled input ('${via}') decides which URL the server requests. An attacker can point it at internal services, cloud metadata (169.254.169.254) or localhost. ` +
    `Allow only known hosts (compare the parsed URL's Hostname() against an allow-list), refuse private addresses, and do not follow redirects blindly.`;
  let ssrfTarget: SyntaxNode | undefined;
  if (HTTP_FUNCTION.test(name)) ssrfTarget = /^fasthttp\./.test(name) ? args[1] : first;
  else if (name === "http.NewRequest") ssrfTarget = args[1];
  else if (name === "http.NewRequestWithContext") ssrfTarget = args[2];
  else if (dot !== -1 && HTTP_CLIENT_METHOD.test(method) && HTTP_CLIENT_RECEIVER.test(receiverText) && !roots.contexts.has(chainOf(call.childForFieldName("function") as SyntaxNode)?.root ?? "")) ssrfTarget = first;
  else if (dot !== -1 && /^(?:SetRequestURI|SetURL|SetBaseURL)$/.test(method)) ssrfTarget = first;
  if (ssrfTarget && !hasFixedHost(ssrfTarget)) specs.push({ rule: "ssrf", severity: "high", confidence: "medium", args: [ssrfTarget], message: ssrfMessage });

  // Redirects
  const redirectMessage = (via: string): string =>
    `User-controlled input ('${via}') decides where the visitor is sent. A link on your site can then lead to a look-alike page that asks for the password. ` +
    `Redirect only to a path of this site (it starts with a single "/", not "//"), or compare the parsed host against an allow-list.`;
  if (name === "http.Redirect" && args[2]) {
    const target = redirectTarget(args[2]);
    if (target.length > 0) specs.push({ rule: "open-redirect", severity: "medium", confidence: "medium", args: target, message: redirectMessage });
  }
  if (dot !== -1 && method === "Redirect" && name !== "http.Redirect") {
    const chain = chainOf(call.childForFieldName("function") as SyntaxNode);
    if (chain && roots.contexts.has(chain.root)) {
      // gin / echo: c.Redirect(302, url); fiber: c.Redirect(url) or c.Redirect(url, 302)
      const target = args.length >= 2 && !isStringLiteral(args[0]) && /^(?:http\.Status|\d)/.test(args[0]?.text ?? "") ? args[1] : args[0];
      const aimed = redirectTarget(target);
      if (aimed.length > 0) specs.push({ rule: "open-redirect", severity: "medium", confidence: "medium", args: aimed, message: redirectMessage });
    }
  }
  if (dot !== -1 && /^(?:Set|Add)$/.test(method) && /\.Header\(\)$/.test(receiverText) && /^["`]Location["`]$/i.test(first?.text ?? "") && args[1]) {
    const aimed = redirectTarget(args[1]);
    if (aimed.length > 0) specs.push({ rule: "open-redirect", severity: "medium", confidence: "medium", args: aimed, message: redirectMessage });
  }

  // CORS: the Origin header copied into Access-Control-Allow-Origin
  if (dot !== -1 && /^(?:Set|Add|Header)$/.test(method) && /^["`]Access-Control-Allow-Origin["`]$/i.test(first?.text ?? "") && args[1]) {
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
  if (writesToResponse(name, first, roots)) specs.push({ rule: "xss", severity: "high", confidence: "medium", args: args.slice(1), message: XSS_MESSAGE });
  if (dot !== -1 && /^(?:Write|WriteString)$/.test(method)) {
    const chain = chainOf(call.childForFieldName("function") as SyntaxNode);
    const onResponse = !!chain && (roots.writers.has(chain.root) && chain.members.length === 1 ? true : roots.contexts.has(chain.root) && chain.members[0] === "Writer");
    if (onResponse && first) specs.push({ rule: "xss", severity: "high", confidence: "medium", args: [first], message: XSS_MESSAGE });
  }
  if (dot !== -1 && method === "Data" && /html/i.test(args[1]?.text ?? "") && args[2]) {
    const chain = chainOf(call.childForFieldName("function") as SyntaxNode);
    if (chain && roots.contexts.has(chain.root)) specs.push({ rule: "xss", severity: "high", confidence: "medium", args: [args[2]], message: XSS_MESSAGE });
  }
  if (dot !== -1 && method === "HTML" && args.length === 2) {
    // echo: c.HTML(200, "<p>...</p>") sends the string as HTML
    const chain = chainOf(call.childForFieldName("function") as SyntaxNode);
    if (chain && roots.contexts.has(chain.root) && args[1]) specs.push({ rule: "xss", severity: "high", confidence: "medium", args: [args[1]], message: XSS_MESSAGE });
  }
  if (/^template\.(?:HTML|JS|CSS|HTMLAttr|URL|JSStr|Srcset)$/.test(name) && first) {
    specs.push({
      rule: "xss",
      severity: "high",
      confidence: "medium",
      args: [first],
      message: (via) =>
        `User-controlled input ('${via}') is marked as safe with ${name}(...), which switches html/template's escaping off for it. A value with <script> runs in your visitors' browsers. ` +
        `Pass the plain string to the template (it escapes it) and use ${name} only for text you wrote.`,
    });
  }

  // A template or script built from the request
  if (dot !== -1 && method === "Parse" && /^template\.(?:Must\()?(?:\w+\.)?New\(/.test(receiverText) && first) {
    specs.push({
      rule: "code-injection",
      severity: "high",
      confidence: "medium",
      args: [first],
      message: (via) =>
        `User-controlled input ('${via}') becomes the template itself. Template actions in it ({{ ... }}) can read fields and call methods of the data you hand to Execute, and text/template does no escaping at all. ` +
        `Keep templates in files you wrote and pass the value as data.`,
    });
  }
  if (dot !== -1 && /^(?:RunString|DoString|RunScript|Eval|Compile)$/.test(method) && /(?:^|[._])(?:vm|js|goja|otto|lua|interp|interpreter|L)$/i.test(receiverText) && first) {
    specs.push({
      rule: "code-injection",
      severity: "critical",
      confidence: "medium",
      args: [first],
      message: (via) => `User-controlled input ('${via}') is run as a script by an embedded interpreter. Anything the script can reach (the host objects you expose, the network, files) is reachable by the caller. Do not evaluate request text; map the request onto fixed operations instead.`,
    });
  }

  return specs;
}

export { literalValue, isStringLiteral };
