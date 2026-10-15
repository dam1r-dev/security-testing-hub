import { checkBudgetNow } from "../budget";
import { Analyzer } from "../analyzers/base-analyzer";
import { ParsedFile, SupportedLanguage } from "../parsers/ast-parser";
import { SyntaxNode, findNodes, snippet, toLocation } from "../parsers/utils";
import { findKnownSecrets, isPlaceholder, isSensitiveName, isSigningSecretName, looksLikeSecret, normalizeName, redact } from "../secrets/detect";
import { Finding, Severity, VulnerabilityType } from "../types";
import { argumentsOf, calleeName, carriedBy, isRequestObject, trackTaint } from "./engine";

/**
 * The PHP rules (plain scripts, Laravel, Symfony): data flow from `$_GET` / `$_POST` / `$request->input()` into SQL, shell commands,
 * `eval` and file inclusion, deserialization, file paths, outgoing requests, redirects and `echo`; plus mass assignment
 * (`Model::create($request->all())`), debug output left on, and secrets written in the code. See engine.ts for what carries a value
 * on and what cleans it. Helpers defined in the same file are followed one call deep; other files are not.
 */

const ROTATE =
  "Treat it as already leaked: revoke / rotate it now (removing the line is not enough: it stays in the git history), " +
  "then load the new value from an environment variable (getenv(\"NAME\") / Laravel's env()) or a secret manager.";

interface Sink {
  rule: VulnerabilityType;
  severity: Severity;
  confidence: "high" | "medium" | "low";
  args: SyntaxNode[];
  message: (via: string) => string;
}

const SQL_FUNCTION_ARG1 = new Set(["mysqli_query", "mysqli_multi_query", "mysqli_real_query", "pg_query", "pg_send_query", "sqlsrv_query", "odbc_exec"]);
const SQL_FUNCTION_ARG0 = new Set(["mysql_query", "mysql_unbuffered_query", "sqlite_query", "sqlite_exec", "db_query"]);
const SQL_METHOD = new Set(["query", "exec", "prepare", "real_query", "multi_query", "unprepared", "statement", "selectRaw", "whereRaw", "orWhereRaw", "havingRaw", "orderByRaw", "groupByRaw", "fromRaw", "joinRaw", "raw"]);
const SQL_STATIC = /^(?:DB|Capsule|Schema)::(?:select|insert|update|delete|statement|unprepared|raw|selectOne|scalar|cursor)$/;
const SHELL_FUNCTION = new Set(["system", "exec", "shell_exec", "passthru", "popen", "proc_open", "pcntl_exec", "expect_popen"]);
const FILE_ARG0 = new Set(["file_get_contents", "fopen", "readfile", "file", "file_put_contents", "unlink", "rmdir", "mkdir", "fpassthru", "highlight_file", "show_source", "scandir", "opendir", "glob", "parse_ini_file", "is_file", "is_dir", "file_exists", "touch", "chmod", "readlink", "simplexml_load_file", "md5_file", "sha1_file", "fileperms", "filesize", "filemtime", "ZipArchive::open", "imagecreatefromjpeg", "imagecreatefrompng"]);
const FILE_ARG01 = new Set(["copy", "rename", "symlink", "link"]);
const FILE_ARG1 = new Set(["move_uploaded_file"]);
const SSRF_FUNCTION = new Set(["curl_init", "fsockopen", "pfsockopen", "get_headers", "getimagesize", "stream_socket_client", "gethostbyname"]);
const DESERIALIZE = new Set(["unserialize", "yaml_parse", "maybe_unserialize"]);
const MODEL_WRITE = new Set(["create", "update", "fill", "forceFill", "insert", "firstOrCreate", "updateOrCreate", "forceCreate", "upsert", "updateOrInsert", "setAttributes"]);

// `https://api.example.com/x/` . $id: the scheme and the whole host are written in the code.
const FIXED_HOST = /^["']https?:\/\/[A-Za-z0-9.-]+(?::\d+)?[/?#]/i;

function firstText(node: SyntaxNode | undefined): string {
  if (!node) return "";
  if (node.type === "binary_expression") return firstText(node.childForFieldName("left") ?? undefined);
  return node.text;
}

function sql(via: string): string {
  return (
    `User-controlled input ('${via}') flows into a SQL query without parameterization. Use a prepared statement with bound values: ` +
    `$stmt = $pdo->prepare("SELECT ... WHERE id = ?"); $stmt->execute([$value]); (Laravel: DB::select("... WHERE id = ?", [$value]) or the query builder) instead of putting the variable into the text.`
  );
}

function sinksOf(node: SyntaxNode, text: string): Sink[] {
  const out: Sink[] = [];
  const name = calleeName(node);
  const args = node.type === "function_call_expression" || node.type === "member_call_expression" || node.type === "scoped_call_expression" || node.type === "object_creation_expression" ? argumentsOf(node) : [];

  if (node.type === "function_call_expression") {
    const lower = name.toLowerCase();
    const arg = (i: number): SyntaxNode[] => (args[i] ? [args[i] as SyntaxNode] : []);
    if (SQL_FUNCTION_ARG1.has(lower)) out.push({ rule: "sql-injection", severity: "critical", confidence: "medium", args: arg(1), message: sql });
    if (SQL_FUNCTION_ARG0.has(lower)) out.push({ rule: "sql-injection", severity: "critical", confidence: "medium", args: arg(0), message: sql });
    if (SHELL_FUNCTION.has(lower)) {
      out.push({
        rule: "command-injection",
        severity: "critical",
        confidence: "medium",
        args: arg(0),
        message: (via) =>
          `User-controlled input ('${via}') flows into a shell command (${name}). ; | && $( ) in it become commands. ` +
          `Avoid the shell (use PHP functions), or build the command from fixed text plus escapeshellarg($value) for each value, and validate the value first.`,
      });
    }
    if (lower === "eval" || lower === "assert" || lower === "create_function" || lower === "call_user_func" || lower === "call_user_func_array" || lower === "preg_replace_callback") {
      out.push({
        rule: "code-injection",
        severity: "critical",
        confidence: "medium",
        args: arg(0),
        message: (via) => `User-controlled input ('${via}') is evaluated as PHP code or chosen as the function to call (${name}). Anyone who controls it runs commands on your server. Use a fixed list of allowed names (a match / array lookup) instead.`,
      });
    }
    if (DESERIALIZE.has(lower)) {
      out.push({
        rule: "insecure-deserialization",
        severity: "critical",
        confidence: "medium",
        args: arg(0),
        message: (via) => `User-controlled input ('${via}') is passed to ${name}(), which can instantiate objects and run their magic methods (gadget chains lead to code execution). Use json_decode, or unserialize($data, ["allowed_classes" => false]).`,
      });
    }
    if (FILE_ARG0.has(lower) || FILE_ARG01.has(lower) || FILE_ARG1.has(lower)) {
      const target = FILE_ARG1.has(lower) ? arg(1) : FILE_ARG01.has(lower) ? args.slice(0, 2) : arg(0);
      const fixedHost = FIXED_HOST.test(firstText(target[0]));
      if (!fixedHost) {
        out.push({
          rule: "path-traversal",
          severity: "high",
          confidence: "medium",
          args: target,
          message: (via) =>
            `User-controlled input ('${via}') is used to build a file path (${name}). ../ in it escapes the folder you meant (/etc/passwd, your .env); a URL in it makes the server fetch it. ` +
            `Reduce it to a file name with basename(), join it to a fixed folder, and check that realpath() of the result is still inside that folder.`,
        });
      }
    }
    if (SSRF_FUNCTION.has(lower) && !FIXED_HOST.test(firstText(args[0]))) {
      out.push({
        rule: "ssrf",
        severity: "high",
        confidence: "medium",
        args: arg(0),
        message: (via) =>
          `User-controlled input ('${via}') is used to build a URL or host that the server connects to (${name}). An attacker can point it at internal services (localhost, 169.254.169.254, private IP ranges). Check the host against an allowlist first.`,
      });
    }
    if (lower === "curl_setopt" && /^CURLOPT_URL$/.test(args[1]?.text ?? "") && !FIXED_HOST.test(firstText(args[2]))) {
      out.push({
        rule: "ssrf",
        severity: "high",
        confidence: "medium",
        args: arg(2),
        message: (via) => `User-controlled input ('${via}') is used as the URL of a cURL request. An attacker can point it at internal services (localhost, 169.254.169.254, private IP ranges). Check the host against an allowlist first.`,
      });
    }
    if (lower === "header") {
      const first = args[0];
      if (first && /^["']\s*location\s*:/i.test(firstText(first))) {
        out.push({
          rule: "open-redirect",
          severity: "medium",
          confidence: "medium",
          args: [first],
          message: (via) =>
            `User-controlled input ('${via}') decides where the server redirects. An attacker sends a link on your domain that bounces victims to a phishing site. Redirect only to paths you build yourself, or check the host against an allowlist.`,
        });
      }
    }
    if (lower === "redirect" || lower === "wp_redirect") {
      out.push({
        rule: "open-redirect",
        severity: "medium",
        confidence: "medium",
        args: arg(0),
        message: (via) => `User-controlled input ('${via}') decides where the server redirects. An attacker sends a link on your domain that bounces victims to a phishing site. Redirect only to paths you build yourself (route(), url()), or check the host against an allowlist.`,
      });
    }
    if (lower === "extract") {
      out.push({
        rule: "code-injection",
        severity: "high",
        confidence: "low",
        args: arg(0),
        message: (via) => `extract() turns every key of ${via} into a variable of this script, so a caller can overwrite any variable (an $is_admin flag, a file path). Read the fields you need one by one.`,
      });
    }
  }

  if (node.type === "member_call_expression") {
    const method = name;
    if (SQL_METHOD.has(method)) out.push({ rule: "sql-injection", severity: "critical", confidence: "medium", args: args[0] ? [args[0]] : [], message: sql });
    if (MODEL_WRITE.has(method)) {
      const first = args[0];
      if (first && ((first.type === "member_call_expression" && isRequestObject(first.childForFieldName("object") ?? first) && first.childForFieldName("name")?.text === "all") || /^\$_(?:POST|GET|REQUEST)$/.test(first.text))) {
        out.push({
          rule: "mass-assignment",
          severity: "medium",
          confidence: "medium",
          args: [first],
          message: () =>
            `The whole request (${first.text}) is passed to ${method}(). Whatever fields the caller adds are written too (role, is_admin, balance, price, user_id). ` +
            `Write only the fields you accept: $request->only(["name", "email"]) or $request->validated() with a validation rule for each field, and keep sensitive columns out of $fillable.`,
        });
      }
    }
    if (/^(?:request|get|post|put|delete|patch|head)$/.test(method) && /(?:client|guzzle|http)/i.test(node.childForFieldName("object")?.text ?? "")) {
      const target = method === "request" ? args[1] : args[0];
      if (target && !FIXED_HOST.test(firstText(target))) {
        out.push({
          rule: "ssrf",
          severity: "high",
          confidence: "medium",
          args: [target],
          message: (via) => `User-controlled input ('${via}') is used to build a URL that the server fetches. An attacker can point it at internal services (localhost, 169.254.169.254, private IP ranges). Check the host against an allowlist first.`,
        });
      }
    }
  }

  if (node.type === "scoped_call_expression") {
    if (SQL_STATIC.test(name)) out.push({ rule: "sql-injection", severity: "critical", confidence: "medium", args: args[0] ? [args[0]] : [], message: sql });
    if (/^(?:Redirect::to|Redirect::away|Redirect::intended|URL::to)$/.test(name)) {
      out.push({
        rule: "open-redirect",
        severity: "medium",
        confidence: "medium",
        args: args[0] ? [args[0]] : [],
        message: (via) => `User-controlled input ('${via}') decides where the server redirects. An attacker sends a link on your domain that bounces victims to a phishing site. Redirect only to routes you name (route("home")), or check the host against an allowlist.`,
      });
    }
    if (/^(?:Http|Guzzle)::(?:get|post|put|delete|patch|head)$/.test(name) && args[0] && !FIXED_HOST.test(firstText(args[0]))) {
      out.push({
        rule: "ssrf",
        severity: "high",
        confidence: "medium",
        args: [args[0]],
        message: (via) => `User-controlled input ('${via}') is used to build a URL that the server fetches. An attacker can point it at internal services (localhost, 169.254.169.254, private IP ranges). Check the host against an allowlist first.`,
      });
    }
    if (MODEL_WRITE.has(name.split("::")[1] ?? "") && /^[A-Z]/.test(name)) {
      const first = args[0];
      if (first && ((first.type === "member_call_expression" && isRequestObject(first.childForFieldName("object") ?? first) && first.childForFieldName("name")?.text === "all") || /^\$_(?:POST|GET|REQUEST)$/.test(first.text))) {
        out.push({
          rule: "mass-assignment",
          severity: "medium",
          confidence: "medium",
          args: [first],
          message: () =>
            `The whole request (${first.text}) is passed to ${name}(). Whatever fields the caller adds are written too (role, is_admin, balance, price, user_id). ` +
            `Write only the fields you accept: $request->only(["name", "email"]) or $request->validated() with a validation rule for each field, and keep sensitive columns out of $fillable.`,
        });
      }
    }
  }

  if (node.type === "include_expression" || node.type === "include_once_expression" || node.type === "require_expression" || node.type === "require_once_expression") {
    const target = node.namedChild(0);
    if (target) {
      out.push({
        rule: "code-injection",
        severity: "critical",
        confidence: "medium",
        args: [target],
        message: (via) =>
          `User-controlled input ('${via}') decides which file PHP includes. A caller can include any file on the server (local file inclusion) and, if allow_url_include is on or an upload is reachable, run their own code. ` +
          `Map the value to a fixed list of pages (a switch or an array lookup) instead of building the path from it.`,
      });
    }
  }

  if (node.type === "echo_statement" || node.type === "print_intrinsic" || node.type === "exit_statement" || node.type === "expression_statement") {
    out.push({
      rule: "xss",
      severity: "high",
      confidence: "medium",
      args: node.namedChildren,
      message: (via) =>
        `User-controlled input ('${via}') is written into the page without escaping. A value with <script> runs in your visitors' browsers. ` +
        `Escape it for HTML: htmlspecialchars($value, ENT_QUOTES, "UTF-8") (Laravel Blade's {{ }} does it for you; {!! !!} does not).`,
    });
  }

  if (node.type === "shell_command_expression") {
    out.push({
      rule: "command-injection",
      severity: "critical",
      confidence: "medium",
      args: [node],
      message: (via) => `User-controlled input ('${via}') flows into a shell command written with backticks. ; | && $( ) in it become commands. Avoid the shell, or pass each value through escapeshellarg().`,
    });
  }
  void text;
  return out;
}

function parameterNames(fn: SyntaxNode): Array<{ name: string; type: string }> {
  const out: Array<{ name: string; type: string }> = [];
  for (const parameter of fn.childForFieldName("parameters")?.namedChildren ?? []) {
    if (parameter.type !== "simple_parameter" && parameter.type !== "variadic_parameter" && parameter.type !== "property_promotion_parameter") continue;
    const name = parameter.childForFieldName("name");
    if (name) out.push({ name: name.text, type: parameter.childForFieldName("type")?.text ?? "" });
  }
  return out;
}

const NUMERIC_TYPE = /^\??(?:int|integer|float|bool|boolean)$/i;
const FRAMEWORK_TYPE = /(?:Request|Response|Model|Authenticatable|Guard|Session|Connection|Builder|Collection|Closure)$/;

/** A public controller action (`public function show(Request $request, $id)`) gets its URL parameters from the caller. */
function controllerOrigins(method: SyntaxNode): string[] {
  const klass = method.parent?.parent;
  if (klass?.type !== "class_declaration") return [];
  const className = klass.childForFieldName("name")?.text ?? "";
  const isController = /Controller$/.test(className) || /extends\s+(?:\\?[\w\\]*Controller|\\?[\w\\]*BaseController)/.test(klass.text.slice(0, 200));
  if (!isController) return [];
  const modifier = method.namedChildren.find((c) => c.type === "visibility_modifier")?.text ?? "public";
  if (modifier !== "public" || method.childForFieldName("name")?.text.startsWith("__")) return [];
  return parameterNames(method)
    .filter((p) => !NUMERIC_TYPE.test(p.type) && !FRAMEWORK_TYPE.test(p.type))
    .map((p) => p.name);
}

function stringValue(node: SyntaxNode): string | undefined {
  if (node.type === "string") return node.text.slice(1, -1);
  if (node.type === "encapsed_string" && node.namedChildren.every((c) => c.type === "string_content" || c.type === "escape_sequence")) return node.text.slice(1, -1);
  return undefined;
}

function assignedName(literal: SyntaxNode): string | undefined {
  const parent = literal.parent;
  if (!parent) return undefined;
  if (parent.type === "assignment_expression" && parent.childForFieldName("right")?.id === literal.id) {
    const left = parent.childForFieldName("left");
    if (left?.type === "variable_name") return left.text.replace(/^\$/, "");
    if (left?.type === "member_access_expression") return left.childForFieldName("name")?.text;
    if (left?.type === "subscript_expression") {
      const key = left.namedChild(1);
      return key ? stringValue(key) : undefined;
    }
  }
  if (parent.type === "array_element_initializer" && parent.namedChildren.length === 2 && parent.namedChild(1)?.id === literal.id) {
    const key = parent.namedChild(0);
    return key ? stringValue(key) : undefined;
  }
  if (parent.type === "argument" && parent.parent?.type === "arguments") {
    const call = parent.parent.parent;
    if (call?.type === "function_call_expression" && call.childForFieldName("function")?.text === "define") {
      const args = argumentsOf(call);
      if (args[1]?.id === literal.id && args[0]) return stringValue(args[0]);
    }
  }
  if (parent.type === "const_element" || parent.type === "property_element") return parent.namedChild(0)?.text.replace(/^\$/, "");
  return undefined;
}

export class PhpAnalyzer implements Analyzer {
  readonly languages: readonly SupportedLanguage[] = ["php"];

  analyze(parsed: ParsedFile, filePath: string): Finding[] {
    const root = parsed.tree.rootNode;
    const text = parsed.sourceCode;
    const findings: Finding[] = [];
    const seen = new Set<string>();
    const add = (finding: Finding): void => {
      const key = `${finding.ruleId}:${finding.location.startLine}:${finding.location.startColumn}`;
      if (seen.has(key)) return;
      seen.add(key);
      findings.push(finding);
    };

    const functions = findNodes(root, (n) => n.type === "function_definition" || n.type === "method_declaration");
    const scopes: SyntaxNode[] = [root, ...functions, ...findNodes(root, (n) => n.type === "anonymous_function" || n.type === "arrow_function")];
    const byName = new Map<string, SyntaxNode[]>();
    for (const fn of functions) {
      const name = fn.childForFieldName("name")?.text;
      if (name) byName.set(name, [...(byName.get(name) ?? []), fn]);
    }

    // 1. What a helper does with its parameters (followed one call deep).
    const summaries = new Map<SyntaxNode, Map<number, { line: number; sink: Sink }>>();
    for (const fn of functions) {
      checkBudgetNow();
      const parameters = parameterNames(fn);
      if (parameters.length === 0 || controllerOrigins(fn).length > 0) continue;
      if (!/query|exec|system|shell|popen|eval|include|require|unserialize|file|curl|header|echo|print|fopen|DB::|redirect/.test(fn.text)) continue;
      const hits = new Map<number, { line: number; sink: Sink }>();
      parameters.forEach((p, index) => {
        trackTaint(fn, [p.name], (node, tainted) => {
          if (hits.has(index)) return;
          for (const sink of sinksOf(node, text)) {
            if (sink.args.some((a) => carriedBy(a, tainted) !== undefined)) {
              hits.set(index, { line: node.startPosition.row + 1, sink });
              return;
            }
          }
        });
      });
      if (hits.size > 0) summaries.set(fn, hits);
    }

    const helperFor = (call: SyntaxNode, inside: SyntaxNode): { fn: SyntaxNode; hits: Map<number, { line: number; sink: Sink }> } | undefined => {
      let name: string | undefined;
      if (call.type === "function_call_expression") name = call.childForFieldName("function")?.text;
      else if (call.type === "member_call_expression" && call.childForFieldName("object")?.text === "$this") name = call.childForFieldName("name")?.text;
      else if (call.type === "scoped_call_expression" && /^(?:self|static)$/.test(call.childForFieldName("scope")?.text ?? "")) name = call.childForFieldName("name")?.text;
      if (!name) return undefined;
      const candidates = byName.get(name) ?? [];
      if (candidates.length !== 1) return undefined;
      const fn = candidates[0] as SyntaxNode;
      const hits = summaries.get(fn);
      return hits && fn.id !== inside.id ? { fn, hits } : undefined;
    };

    // 2. The data flow, scope by scope (the top level of the file, each function and method).
    for (const scope of scopes) {
      checkBudgetNow();
      const origins = scope.type === "method_declaration" ? controllerOrigins(scope) : [];
      const guarded = /parse_url|in_array\s*\(|allowed_hosts|wp_validate_redirect|wp_safe_redirect/.test(scope.text);
      trackTaint(scope, origins, (node, tainted) => {
        for (const sink of sinksOf(node, text)) {
          if (sink.rule === "open-redirect" && guarded) continue;
          for (const arg of sink.args) {
            const via = carriedBy(arg, tainted);
            if (via === undefined) continue;
            add({
              ruleId: sink.rule,
              severity: sink.severity,
              confidence: sink.confidence,
              message: sink.message(via),
              location: toLocation(node, filePath),
              sourceSnippet: via,
              sinkSnippet: snippet(node, text),
            });
            break;
          }
        }
        const helper = scope.type === "program" || scope.type === "method_declaration" || scope.type === "function_definition" ? helperFor(node, scope) : undefined;
        if (helper) {
          const callArgs = argumentsOf(node);
          for (const [index, hit] of helper.hits) {
            const arg = callArgs[index];
            const via = arg ? carriedBy(arg, tainted) : undefined;
            if (via === undefined) continue;
            add({
              ruleId: hit.sink.rule,
              severity: hit.sink.severity,
              confidence: hit.sink.confidence,
              message: `${hit.sink.message(via)} The value is passed to ${calleeName(node)}() and reaches the vulnerable call at line ${hit.line}.`,
              location: toLocation(node, filePath),
              sourceSnippet: via,
              sinkSnippet: snippet(node, text),
            });
          }
        }
      });
    }

    // 3. Checks that need no data flow.
    for (const call of findNodes(root, (n) => n.type === "function_call_expression")) {
      const name = calleeName(call).toLowerCase();
      const args = argumentsOf(call);
      if (name === "ini_set" && /display_errors/.test(args[0]?.text ?? "") && /^(?:["']?(?:1|on|true|stdout)["']?|true)$/i.test(args[1]?.text ?? "")) {
        add({
          ruleId: "debug-mode",
          severity: "medium",
          confidence: "high",
          message: "display_errors is switched on in the code: PHP prints errors (with file paths, queries and sometimes passwords) into the page for every visitor. Log errors instead (log_errors=1) and keep display_errors off in production.",
          location: toLocation(call, filePath),
          sourceSnippet: "display_errors",
          sinkSnippet: snippet(call, text),
        });
      }
      if (name === "phpinfo" && args.length <= 1) {
        add({
          ruleId: "debug-mode",
          severity: "medium",
          confidence: "medium",
          message: "phpinfo() prints the PHP configuration, loaded modules, paths and environment variables (often including secrets) to anyone who can open this file. Remove it from anything that is deployed.",
          location: toLocation(call, filePath),
          sourceSnippet: "phpinfo()",
          sinkSnippet: snippet(call, text),
        });
      }
    }

    // 4. Secrets written in the code.
    const lines = text.split("\n");
    for (const match of findKnownSecrets(text)) {
      const before = text.slice(0, match.index);
      const line = before.split("\n").length;
      const column = match.index - before.lastIndexOf("\n");
      add({
        ruleId: "hardcoded-secret",
        severity: match.secret.severity,
        confidence: "high",
        message: `A ${match.secret.label} is written into the source code (${redact(match.text)}). Anyone who can read this repository can use it. ${ROTATE}`,
        location: { file: filePath, startLine: line, startColumn: column, endLine: line, endColumn: column + match.text.length },
        sourceSnippet: redact(match.text),
        sinkSnippet: (lines[line - 1] ?? "").split(match.text).join("<redacted>").trim().slice(0, 160),
      });
    }
    for (const literal of findNodes(root, (n) => n.type === "string" || n.type === "encapsed_string")) {
      const value = stringValue(literal);
      const rawName = value === undefined ? undefined : assignedName(literal);
      if (value === undefined || !rawName || value.length < 4) continue;
      const name = normalizeName(rawName);
      if (isPlaceholder(value)) continue;
      const signing = isSigningSecretName(name);
      if (!signing && !(isSensitiveName(name) && looksLikeSecret(value, name))) continue;
      if (signing && !looksLikeSecret(value, name) && value.length < 8) continue;
      add({
        ruleId: "hardcoded-secret",
        severity: "high",
        confidence: signing ? "high" : "medium",
        message: signing
          ? `\`${rawName}\` is a string written in the code (${redact(value)}) and is used to sign sessions or tokens. Anyone who reads the code can forge logins. Use a long random value from the environment (getenv("${name.toUpperCase()}")).`
          : `\`${rawName}\` is assigned a string that looks like a real credential (${redact(value)}). ${ROTATE}`,
        location: toLocation(literal, filePath),
        sourceSnippet: redact(value),
        sinkSnippet: (lines[literal.startPosition.row] ?? "").split(value).join("<redacted>").trim().slice(0, 160),
      });
    }
    return findings;
  }
}
