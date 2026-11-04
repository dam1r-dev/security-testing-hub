import { SyntaxNode, findNodes, snippet, toLocation } from "../parsers/utils";
import { Finding, Severity, VulnerabilityType } from "../types";
import { argumentsOf, calleeName } from "./engine";

/**
 * The PHP side of `debug-endpoint` and the upload half of `insecure-file-upload` (reasoning in analyzers/exposure.ts). Plain patterns:
 *
 *  - `phpinfo()` left in a page (the whole PHP configuration, paths, environment variables, loaded modules), `print_r($_ENV)`,
 *    `var_dump($_SERVER)`, `json_encode(getenv())`: the environment in a response;
 *  - `move_uploaded_file($tmp, $dir . $_FILES["f"]["name"])` (or the name kept in a variable), Laravel's `->move($dir, $file->getClientOriginalName())`
 *    / `->storeAs(..., getClientOriginalName())`, with no extension or MIME check anywhere in the same function.
 */

const CLIENT_NAME = /\$_FILES\s*\[[^\]]+\]\s*\[\s*['"]name['"]\s*\]|getClientOriginalName\s*\(|getClientOriginalExtension\s*\(/;
const WHOLE = /^(?:\$_ENV|\$_SERVER|\$GLOBALS|getenv\(\s*\)|get_defined_vars\(\s*\))$/;
const DUMP = new Set(["var_dump", "print_r", "var_export", "json_encode", "serialize", "debug_zval_dump"]);
const UPLOAD_CHECK = /pathinfo|in_array|getimagesize|exif_imagetype|finfo|mime_content_type|allowed|whitelist|extension|\$ext\b|preg_match|\['type'\]|["']type["']|_type\b|mime|->validate|validate\(|mimes:|image\||ClientMimeType|sanitize|wp_unique_filename|slugify|uniqid\(\)\s*\.\s*["']\.(?:jpg|png)/i;
const LOGIN = /login|auth|admin|session|isAdmin|authenticated|Auth::|middleware|permission|role/i;
const CLI = /php_sapi_name|PHP_SAPI/;

type Make = (rule: VulnerabilityType, severity: Severity, node: SyntaxNode, message: string, confidence?: Finding["confidence"]) => void;

function scopeOf(node: SyntaxNode, root: SyntaxNode): SyntaxNode {
  for (let p: SyntaxNode | null = node.parent; p; p = p.parent) if (p.type === "function_definition" || p.type === "method_declaration") return p;
  return root;
}

export function exposureFindings(root: SyntaxNode, text: string, filePath: string): Finding[] {
  if (!/phpinfo|\$_ENV|\$_SERVER|getenv|move_uploaded_file|getClientOriginal|\$GLOBALS|get_defined_vars/.test(text)) return [];
  const findings: Finding[] = [];
  const seen = new Set<string>();
  const make: Make = (rule, severity, node, message, confidence = "medium") => {
    const key = `${rule}:${node.startIndex}`;
    if (seen.has(key)) return;
    seen.add(key);
    findings.push({ ruleId: rule, severity, confidence, message, location: toLocation(node, filePath), sourceSnippet: "(code pattern)", sinkSnippet: snippet(node, text) });
  };

  for (const call of findNodes(root, (n) => n.type === "function_call_expression" || n.type === "member_call_expression")) {
    const name = calleeName(call);
    const lower = name.toLowerCase();
    const args = argumentsOf(call);

    if (call.type === "function_call_expression" && lower === "phpinfo" && !CLI.test(text)) {
      // a page that checks the login first is still a page that shows the configuration: lower confidence, same finding
      make(
        "debug-endpoint",
        "high",
        call,
        "phpinfo() prints the whole PHP configuration: version, file paths, loaded modules and every environment variable the server was started with. Anyone who can open this page learns how to attack the server. " +
          "Delete the page (it is a development helper); if you still need it, restrict it to your own IP address.",
        LOGIN.test(text) ? "low" : "medium",
      );
    }

    // var_dump($_SERVER), print_r($_ENV), json_encode(getenv())
    if (call.type === "function_call_expression" && DUMP.has(lower) && args[0] && WHOLE.test(args[0].text.trim())) {
      make(
        "debug-endpoint",
        "high",
        call,
        `${name}(${args[0].text.trim()}) prints the whole environment of the server: variables the server was started with (database password, API keys) and request headers with credentials. ` +
          "Remove it; while debugging, log the one value you need on the server and never put it in the page.",
      );
    }

    // move_uploaded_file($_FILES["f"]["tmp_name"], $dir . basename($_FILES["f"]["name"]))
    const isMove = call.type === "function_call_expression" && lower === "move_uploaded_file";
    const isLaravel = call.type === "member_call_expression" && /^(?:move|storeAs|storePubliclyAs)$/.test(name);
    if (isMove || isLaravel) {
      const scope = scopeOf(call, root);
      if (UPLOAD_CHECK.test(scope.text)) continue;
      // `$target = $dir . basename($_FILES["f"]["name"]);` one hop back (also `.=`)
      const named = new Set<string>();
      for (const assignment of findNodes(scope, (n) => n.type === "assignment_expression" || n.type === "augmented_assignment_expression")) {
        const left = assignment.childForFieldName("left");
        const right = assignment.childForFieldName("right");
        if (left?.type === "variable_name" && right && CLIENT_NAME.test(right.text)) named.add(left.text);
      }
      const target = (isMove ? args.slice(1, 2) : args).map((a) => a.text).join(" ");
      const clientName = CLIENT_NAME.test(target) || [...named].some((n) => target.includes(n));
      if (!clientName) continue;
      make(
        "insecure-file-upload",
        "high",
        call,
        "The upload is stored under the file name the browser sent, and nothing in this function checks the extension or the type. A name like shell.php uploaded into a served folder runs as code on your server, and ../ in the name writes outside the folder. " +
          "Build the name yourself (bin2hex(random_bytes(16)) plus an extension taken from an allow-list such as ['jpg', 'png']), check the extension with pathinfo() and the content with finfo / getimagesize(), and keep uploads outside the web root.",
      );
    }
  }
  return findings;
}
