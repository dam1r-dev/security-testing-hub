import { SyntaxNode, findNodes, snippet, toLocation } from "../parsers/utils";
import { Finding, Severity, VulnerabilityType } from "../types";
import { calleeText, callArguments } from "./engine";

/**
 * The Python side of `debug-endpoint` and the upload half of `insecure-file-upload` (JavaScript side and reasoning: analyzers/exposure.ts,
 * analyzers/insecure-file-upload.ts). Plain patterns, no data flow.
 *
 *  - the whole environment or the whole Flask config in a response (`jsonify(dict(os.environ))`, `return str(os.environ)`): every secret the
 *    server was started with;
 *  - a route named like a debugging page (`/debug`, `/_debug`, `/heapdump`) with no sign of a login check;
 *  - an upload saved under the name the browser sent (`file.save(os.path.join(DIR, file.filename))`, `open(f"uploads/{f.filename}", "wb")`,
 *    `default_storage.save(f.name, f)`) with no `secure_filename` and no check of the extension: `../../app.py`, `shell.php`, `index.html`.
 */

// os.environ as a whole (not os.environ["X"], os.environ.get("X")); the Flask config as a whole
const WHOLE_ENVIRONMENT = /(?<![\w.])os\.environ(?:\.(?:items|copy|keys|values)\(\))?(?![\w.[])/;
const WHOLE_CONFIG = /(?<![\w.])(?:current_app|app)\.config(?:\.items\(\))?(?![\w.[])/;
const RESPONDER = /^(?:jsonify|JsonResponse|JSONResponse|Response|HttpResponse|PlainTextResponse|make_response|json\.dumps|render_template|render)$/;
const DEBUG_PATH = /^\/(?:_{0,2}debug\w*|heapdump|phpinfo|server-status|server-info|_profiler|api\/debug|admin\/debug|debug\/\w+)(?:\/|$)/i;
const GUARD = /login_required|auth|admin|permission|role|jwt|token|session|Depends\(|abort\(40[13]\)|is_authenticated|is_staff|is_superuser|current_user|api[_-]?key/i;
// only mounted while developing: `if app.debug:`, `if DEBUG:`, `if os.environ.get("FLASK_ENV") == "development":`
const DEV_ONLY = /app\.debug|current_app\.debug|\bDEBUG\b|\bFLASK_(?:ENV|DEBUG)\b|\bENV(?:IRONMENT)?\b/;
const UPLOAD_SCOPE = /request\.files|request\.FILES|UploadFile|\bFileStorage\b/;
const UPLOAD_CHECK = /secure_filename|get_valid_filename|ALLOWED|allowed|splitext|rsplit\(|\.suffix\b|endswith\(|content_type|mimetype|imghdr|magic|filetype|extension|uuid|sanitiz|safe_\w*name|secure_\w*name|slugify|clean_filename/i;

type Make = (rule: VulnerabilityType, severity: Severity, node: SyntaxNode, message: string, confidence?: Finding["confidence"]) => void;

function stringValue(node: SyntaxNode | null | undefined): string | undefined {
  if (!node || node.type !== "string") return undefined;
  return node.text.replace(/^[rbfuRBFU]*("""|'''|"|')/, "").replace(/("""|'''|"|')$/, "");
}

function enclosingFunction(node: SyntaxNode): SyntaxNode | undefined {
  for (let p: SyntaxNode | null = node.parent; p; p = p.parent) if (p.type === "function_definition") return p;
  return undefined;
}

export function exposureFindings(root: SyntaxNode, text: string, filePath: string): Finding[] {
  if (!/os\.environ|app\.config|debug|heapdump|_profiler|request\.files|request\.FILES|UploadFile/i.test(text)) return [];
  const findings: Finding[] = [];
  const seen = new Set<string>();
  const make: Make = (rule, severity, node, message, confidence = "medium") => {
    const key = `${rule}:${node.startIndex}`;
    if (seen.has(key)) return;
    seen.add(key);
    findings.push({ ruleId: rule, severity, confidence, message, location: toLocation(node, filePath), sourceSnippet: "(code pattern)", sinkSnippet: snippet(node, text) });
  };

  const environmentMessage = (what: string): string =>
    `This response contains ${what}: every secret the server was started with (database password, API keys, SECRET_KEY) goes to whoever opens the URL. ` +
    "Remove the route. If you need to see one setting while debugging, print that one value in the server log and never in a response.";

  for (const call of findNodes(root, (n) => n.type === "call")) {
    const name = calleeText(call);
    const { positional } = callArguments(call);

    // jsonify(dict(os.environ)), JsonResponse(dict(os.environ)), HttpResponse(str(os.environ)), jsonify(app.config)
    if (RESPONDER.test(name) && positional.length > 0) {
      const argsText = positional.map((a) => a.text).join(" ");
      if (WHOLE_ENVIRONMENT.test(argsText)) make("debug-endpoint", "high", call, environmentMessage("the whole environment (os.environ)"));
      else if (WHOLE_CONFIG.test(argsText)) make("debug-endpoint", "high", call, environmentMessage("the whole application config (app.config, with SECRET_KEY)"));
    }

    // file.save(os.path.join(DIR, file.filename)), default_storage.save(f.name, f), open(f"uploads/{f.filename}", "wb")
    const isSave = /(?:^|\.)save$/.test(name);
    const isOpen = name === "open" || name === "io.open" || name === "builtins.open";
    if (isSave || isOpen) {
      const fn = enclosingFunction(call);
      const scope = fn?.text ?? "";
      if (!UPLOAD_SCOPE.test(scope) || UPLOAD_CHECK.test(scope)) continue;
      const fromFiles = /request\.FILES/.test(scope);
      // `filename = file.filename` one hop back
      const named = new Set<string>();
      for (const assignment of findNodes(fn as SyntaxNode, (n) => n.type === "assignment")) {
        const left = assignment.childForFieldName("left");
        const right = assignment.childForFieldName("right");
        if (left?.type === "identifier" && right && (/\.filename\b/.test(right.text) || (fromFiles && /\.name\b/.test(right.text)))) named.add(left.text);
      }
      const arg = positional.find((a, index) => (isSave ? index === 0 || a.type === "call" : index === 0)) ?? positional[0];
      const argText = arg?.text ?? "";
      const clientName = /\.filename\b/.test(argText) || (fromFiles && /\.name\b/.test(argText)) || [...named].some((n) => new RegExp(`(?<![\\w.])${n}\\b`).test(argText));
      if (!clientName) continue;
      if (isOpen) {
        const mode = stringValue(positional[1]) ?? callArguments(call).keywords.get("mode")?.text.replace(/["']/g, "") ?? "";
        if (!/[wa]/.test(mode)) continue;
      }
      make(
        "insecure-file-upload",
        "high",
        call,
        "The upload is saved under the file name the browser sent, with no check of the extension. A name like ../../app.py writes outside the folder, and shell.php, index.html or a .py file " +
          "uploaded into a served folder runs or serves attacker-controlled code. Build the name yourself (uuid4().hex plus an extension from an allow-list such as {'.png', '.jpg'}), " +
          "or at least pass it through werkzeug.utils.secure_filename, and check the extension.",
      );
    }
  }

  // return str(os.environ) / return dict(os.environ): a view that returns the environment
  for (const ret of findNodes(root, (n) => n.type === "return_statement")) {
    const value = ret.namedChild(0);
    if (!value || (value.type === "call" && RESPONDER.test(calleeText(value)))) continue; // a responder call is judged above
    const direct = WHOLE_ENVIRONMENT.test(value.text) ? "the whole environment (os.environ)" : WHOLE_CONFIG.test(value.text) ? "the whole application config (app.config, with SECRET_KEY)" : undefined;
    const route = enclosingFunction(ret)?.parent;
    if (direct && route?.type === "decorated_definition" && /@\w+\.(?:route|get|post|api_route)\b/.test(route.text.slice(0, 200))) make("debug-endpoint", "high", ret, environmentMessage(direct));
  }

  // @app.route("/debug"): a debugging page with nothing that looks like a login check
  for (const decorated of findNodes(root, (n) => n.type === "decorated_definition")) {
    const decorators = decorated.namedChildren.filter((c) => c.type === "decorator");
    const route = decorators.map((d) => /\.(?:route|get|post|api_route)\(\s*["']([^"']+)["']/.exec(d.text)?.[1]).find((p) => p !== undefined);
    if (route === undefined || !DEBUG_PATH.test(route)) continue;
    const fn = decorated.namedChildren.find((c) => c.type === "function_definition");
    const developmentOnly = ((): boolean => {
      for (let p: SyntaxNode | null = decorated.parent; p; p = p.parent) if (p.type === "if_statement" && DEV_ONLY.test(p.childForFieldName("condition")?.text ?? "")) return true;
      return false;
    })();
    if (!fn || developmentOnly || GUARD.test(decorators.map((d) => d.text).join(" ")) || GUARD.test(fn.text) || DEV_ONLY.test(fn.text) || !/\breturn\b/.test(fn.text)) continue;
    make(
      "debug-endpoint",
      "medium",
      fn,
      `The route "${route}" looks like a debugging page and nothing in it checks who is asking. Debug routes show configuration, memory or request data that helps an attacker. ` +
        "Delete it, or register it only when the app runs in debug mode on your own machine and put it behind your login.",
      "low",
    );
  }
  return findings;
}
