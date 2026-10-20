import { SyntaxNode } from "../parsers/utils";
import { Severity, VulnerabilityType } from "../types";
import { argumentsOf, calleeName, isRequestObject } from "./engine";

/**
 * The dangerous calls of PHP code and which of their arguments must not be the caller's. engine.ts says whether an argument carries
 * the caller's value; this file says where it must not end up.
 */

export interface Sink {
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

export function sinksOf(node: SyntaxNode, text: string): Sink[] {
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
      if (first && /^["']\s*location\s*:/i.test(firstText(first)) && !/^["']\s*location\s*:\s*\/(?![/\\])/i.test(firstText(first))) {
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
