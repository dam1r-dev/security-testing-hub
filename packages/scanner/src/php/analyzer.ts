import { checkBudgetNow } from "../budget";
import { Analyzer } from "../analyzers/base-analyzer";
import { ParsedFile, SupportedLanguage } from "../parsers/ast-parser";
import { SyntaxNode, findNodes, snippet, toLocation } from "../parsers/utils";
import { isFixturePath } from "../analyzers/hardcoded-secret";
import { bladeUnsafeUse, findTemplate } from "../templates";
import { findKnownSecrets, isPlaceholder, isSensitiveName, isSigningSecretName, looksLikeSecret, normalizeName, redact } from "../secrets/detect";
import { Finding } from "../types";
import { argumentsOf, calleeName, carriedBy, trackTaint } from "./engine";
import { PhpProject, argumentFor, parameterNames } from "./project";
import { ProjectContext } from "../taint/project";
import { sinksOf } from "./sinks";

/**
 * The PHP rules (plain scripts, Laravel, Symfony): data flow from `$_GET` / `$_POST` / `$request->input()` into SQL, shell commands,
 * `eval` and file inclusion, deserialization, file paths, outgoing requests, redirects and `echo`; plus mass assignment
 * (`Model::create($request->all())`), debug output left on, and secrets written in the code. See engine.ts for what carries a value
 * on and what cleans it. Helpers defined in the same file are followed one call deep; other files are not.
 */

const ROTATE =
  "Treat it as already leaked: revoke / rotate it now (removing the line is not enough: it stays in the git history), " +
  "then load the new value from an environment variable (getenv(\"NAME\") / Laravel's env()) or a secret manager.";

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
    // `show(Training $training)`: Laravel loads the model by the id in the URL, so it is a record, not the caller's text
    .filter((p) => !NUMERIC_TYPE.test(p.type) && !FRAMEWORK_TYPE.test(p.type) && !/^\??\\?[A-Z]\w*(?:\\\w+)*$/.test(p.type.replace(/\s/g, "")))
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

/** `view("page", ["k" => $v])`, `view("page", compact("k"))`, `view("page")->with("k", $v)`: the template name and what it is handed. */
function viewCall(node: SyntaxNode): { name: string; values: Array<{ key: string; value: SyntaxNode | string }> } | undefined {
  const isView = (n: SyntaxNode): boolean => (n.type === "function_call_expression" && calleeName(n) === "view") || (n.type === "scoped_call_expression" && /^(?:View::make|Response::view)$/.test(calleeName(n)));
  const values: Array<{ key: string; value: SyntaxNode | string }> = [];
  let root: SyntaxNode | undefined;
  if (isView(node)) root = node;
  else if (node.type === "member_call_expression" && node.childForFieldName("name")?.text === "with") {
    // view("page")->with("k", $v): walk down the chain to the view() call
    let current: SyntaxNode | null = node;
    while (current && current.type === "member_call_expression") {
      if (current.childForFieldName("name")?.text === "with") {
        const [key, value] = argumentsOf(current);
        if (key?.type === "string" && value) values.push({ key: key.text.slice(1, -1), value });
      }
      current = current.childForFieldName("object");
    }
    if (current && isView(current)) root = current;
  }
  if (!root) return undefined;
  const args = argumentsOf(root);
  const first = args[root.type === "scoped_call_expression" ? 0 : 0];
  if (first?.type !== "string") return undefined;
  const data = args[1];
  if (data?.type === "array_creation_expression") {
    for (const element of data.namedChildren) {
      const [key, value] = element.namedChildren;
      if (element.type === "array_element_initializer" && key?.type === "string" && value) values.push({ key: key.text.slice(1, -1), value });
    }
  } else if (data?.type === "function_call_expression" && calleeName(data) === "compact") {
    for (const name of argumentsOf(data)) if (name.type === "string") values.push({ key: name.text.slice(1, -1), value: `$${name.text.slice(1, -1)}` });
  }
  return { name: first.text.slice(1, -1), values };
}

export class PhpAnalyzer implements Analyzer {
  readonly languages: readonly SupportedLanguage[] = ["php"];

  analyze(parsed: ParsedFile, filePath: string, context?: ProjectContext): Finding[] {
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

    // The rest of the project: a call to `find_user($name)` or `UserService::find($name)` is followed into the file that defines it
    // (see project.ts). The index is built the first time a call needs it.
    const project = PhpProject.of(context ?? ProjectContext.forSingleFile(filePath, parsed));
    project.parse(filePath, parsed);

    // 2. The data flow, scope by scope (the top level of the file, each function and method).
    for (const scope of scopes) {
      checkBudgetNow();
      const origins = scope.type === "method_declaration" ? controllerOrigins(scope) : [];
      const guarded = /parse_url|in_array\s*\(|allowed_hosts|wp_validate_redirect|wp_safe_redirect/.test(scope.text);
      // Variables an included file leaves holding the caller's text, by the files that set them: reported with the finding.
      const included = new Map<string, string[]>();
      const fromInclude = (via: string): string => {
        const files = included.get(via);
        return files ? ` ${via} is set by ${files.slice(0, 3).map((f) => project.context.displayPath(f)).join(", ")}, which this file includes.` : "";
      };
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
              message: sink.message(via) + fromInclude(via),
              location: toLocation(node, filePath),
              sourceSnippet: via,
              sinkSnippet: snippet(node, text),
            });
            break;
          }
        }
        // A value handed to a Blade view that prints it raw ({!! $name !!}).
        const view = viewCall(node);
        if (view) {
          const file = findTemplate(project.context.root, view.name, "blade");
          for (const { key, value } of file ? view.values : []) {
            const via = typeof value === "string" ? (tainted.has(value) ? value : undefined) : carriedBy(value, tainted);
            const use = via === undefined || !file ? undefined : bladeUnsafeUse(file, key);
            if (via === undefined || !use) continue;
            add({
              ruleId: "xss",
              severity: "high",
              confidence: "medium",
              message:
                `User-controlled input ('${via}') is handed to the view as $${key}, and ${project.context.displayPath(use.file)}:${use.line} prints it raw (${use.how}). ` +
                `A value with <script> runs in your visitors' browsers. Print it with {{ $${key} }}, which escapes it.`,
              location: toLocation(node, filePath),
              sourceSnippet: via,
              sinkSnippet: snippet(node, text),
            });
          }
        }
        const helper = project.resolve(node, filePath, parsed, scope, tainted);
        if (helper) {
          for (const [index, hit] of project.summary(helper)) {
            const arg = argumentFor(node, helper.fn, index);
            const via = arg ? carriedBy(arg, tainted) : undefined;
            if (via === undefined) continue;
            const place = hit.file === filePath ? `line ${hit.line}` : `${project.context.displayPath(hit.file)}:${hit.line}`;
            const route = hit.chain.length > 0 ? ` (via ${hit.chain.join(" -> ")})` : "";
            add({
              ruleId: hit.sink.rule,
              severity: hit.sink.severity,
              confidence: hit.sink.confidence,
              message: `${hit.sink.message(via)} The value is passed to ${helper.name}() and reaches the vulnerable call at ${place}${route}.${fromInclude(via)}`,
              location: toLocation(node, filePath),
              sourceSnippet: via,
              sinkSnippet: snippet(node, text),
            });
          }
        }
      }, {
        onInclude: (node, tainted) => {
          for (const [name, files] of project.includeExports(node, filePath, parsed)) {
            tainted.add(name);
            included.set(name, files);
          }
        },
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

    // 3b. A JWT read without checking its signature, and CSRF protection switched off (Laravel).
    const at = (index: number): { line: number; column: number } => {
      const before = text.slice(0, index);
      return { line: before.split("\n").length, column: index - before.lastIndexOf("\n") };
    };
    const place = (index: number, length: number): Finding["location"] => {
      const { line, column } = at(index);
      return { file: filePath, startLine: line, startColumn: column, endLine: line, endColumn: column + length };
    };
    const lineAt = (index: number): string => (text.split("\n")[at(index).line - 1] ?? "").trim().slice(0, 160);
    for (const call of findNodes(root, (n) => n.type === "scoped_call_expression" || n.type === "function_call_expression")) {
      const name = calleeName(call);
      const args = argumentsOf(call);
      if (/^(?:Firebase\\JWT\\)?JWT::decode$/.test(name) && /["']none["']/i.test(args[2]?.text ?? "")) {
        add({
          ruleId: "insecure-jwt",
          severity: "critical",
          confidence: "high",
          message: "JWT::decode accepts the \"none\" algorithm: a token without a signature is valid, so anyone can forge a token with any user id or role. Pass only the algorithm you sign with (new Key($secret, \"HS256\")).",
          location: toLocation(call, filePath),
          sourceSnippet: "algorithm none",
          sinkSnippet: snippet(call, text),
        });
      }
      if (name === "base64_decode" && /explode\(\s*["']\.["']/.test(args[0]?.text ?? "")) {
        add({
          ruleId: "insecure-jwt",
          severity: "high",
          confidence: "medium",
          message: "A token's payload is read by splitting it at the dots and decoding the middle part, without checking the signature. Anyone can write such a token. Verify it with a JWT library (JWT::decode with the key and the algorithm) before trusting a claim.",
          location: toLocation(call, filePath),
          sourceSnippet: "payload decoded without verification",
          sinkSnippet: snippet(call, text),
        });
      }
    }
    for (const m of text.matchAll(/\$except\s*=\s*\[[^\]]*["']\*["']|validateCsrfTokens\(\s*except:\s*\[[^\]]*["']\*["']|withoutMiddleware\([^)]*VerifyCsrfToken/g)) {
      add({
        ruleId: "csrf",
        severity: "medium",
        confidence: "high",
        message: "CSRF protection is switched off for every route (or for the route this is attached to): another site can make a signed-in visitor's browser send a form to this application. Remove the exception, and list only the webhook URLs that really cannot send a token.",
        location: place(m.index ?? 0, m[0].length),
        sourceSnippet: "CSRF exception",
        sinkSnippet: lineAt(m.index ?? 0),
      });
    }
    if (/\.blade\.php$/i.test(filePath)) {
      for (const m of text.matchAll(/<form\b[^>]*\bmethod\s*=\s*["']?(?:post|put|patch|delete)["']?[^>]*>([\s\S]*?)<\/form>/gi)) {
        // a form that includes a partial or a component may get its @csrf there: not judged
        if (/@csrf|csrf_field\s*\(|csrf_token\s*\(|name\s*=\s*["']_token["']|@include|@component|@livewire|@each|<x-|<livewire:/.test(m[1] ?? "")) continue;
        add({
          ruleId: "csrf",
          severity: "medium",
          confidence: "medium",
          message: "This form posts data but carries no CSRF token (no @csrf). Laravel rejects such a request when the CSRF middleware is on, so the page is broken, or the protection was switched off for it. Add @csrf inside the form.",
          location: place(m.index ?? 0, Math.min(m[0].length, 80)),
          sourceSnippet: "form without @csrf",
          sinkSnippet: lineAt(m.index ?? 0),
        });
      }
    }

    // 4. Secrets written in the code. (Seeders, fixtures and mocks hold made-up credentials on purpose: judged by name they are noise.)
    const fixtureLike = isFixturePath(filePath);
    const lines = text.split("\n");
    for (const match of findKnownSecrets(text)) {
      if (fixtureLike && /private key/i.test(match.secret.label)) continue;
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
      if (isPlaceholder(value) || fixtureLike) continue;
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
