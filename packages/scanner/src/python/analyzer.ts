import { checkBudgetNow } from "../budget";
import { ParsedFile, SupportedLanguage } from "../parsers/ast-parser";
import { SyntaxNode, findNodes, snippet, toLocation } from "../parsers/utils";
import { isFixturePath } from "../analyzers/hardcoded-secret";
import { findKnownSecrets, isPlaceholder, isSensitiveName, isSigningSecretName, looksLikeSecret, normalizeName, redact } from "../secrets/detect";
import { Finding } from "../types";
import { Analyzer } from "../analyzers/base-analyzer";
import { calleeText, callArguments, carriedBy, trackTaint } from "./engine";
import { decoratorsOf, originsOf, parametersOf } from "./origins";
import { HTML_IN_STRING, SinkSpec, XSS_RETURN_MESSAGE, sinksOf } from "./sinks";

/**
 * The Python rules (Flask, FastAPI, Django) in one analyzer: data flow from the request into SQL, shell, `eval`, deserialization, file
 * paths, outgoing requests, redirects and HTML (engine.ts, sinks.ts), plus the checks that need no data flow: debug mode left on,
 * `csrf_exempt`, a JWT decoded without verification, and secrets written in the code.
 *
 * Data flows through a helper defined in the same file (`def find_user(name): cursor.execute(f"...{name}")`) are followed one call
 * deep. Helpers in other files are not (yet): a value handed to them is not followed.
 */

const DEVELOPMENT_FILE = /(?:^|[/\\_.-])(?:dev|develop|development|local|test|tests|testing|ci|debug)(?:[/\\_.-]|$)/i;

const ROTATE =
  "Treat it as already leaked: revoke / rotate it now (removing the line is not enough: it stays in the git history), " +
  "then load the new value from an environment variable (os.environ[\"NAME\"]) or a secret manager.";

interface Summary {
  /** Index of the parameter -> the sink it reaches. */
  hits: Map<number, { rule: SinkSpec["rule"]; line: number; spec: SinkSpec }>;
}

function strippedString(node: SyntaxNode): string | undefined {
  if (node.type !== "string") return undefined;
  if (node.namedChildren.some((c) => c.type === "interpolation")) return undefined; // an f-string with values in it: not a literal
  const text = node.text;
  const match = /^[rRbBuU]*("""|'''|"|')([\s\S]*)\1$/.exec(text);
  return match ? (match[2] as string) : undefined;
}

function assignedName(literal: SyntaxNode): string | undefined {
  const parent = literal.parent;
  if (!parent) return undefined;
  if (parent.type === "assignment" && parent.childForFieldName("right")?.id === literal.id) {
    const left = parent.childForFieldName("left");
    if (left?.type === "identifier") return left.text;
    if (left?.type === "attribute") return left.childForFieldName("attribute")?.text;
    if (left?.type === "subscript") {
      const key = left.childForFieldName("subscript");
      return key?.type === "string" ? strippedString(key) : undefined;
    }
  }
  if (parent.type === "keyword_argument" && parent.childForFieldName("value")?.id === literal.id) return parent.childForFieldName("name")?.text;
  if (parent.type === "pair" && parent.childForFieldName("value")?.id === literal.id) {
    const key = parent.childForFieldName("key");
    return key?.type === "string" ? strippedString(key) : key?.text;
  }
  return undefined;
}

export class PythonAnalyzer implements Analyzer {
  readonly languages: readonly SupportedLanguage[] = ["python"];

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

    const functions = findNodes(root, (n) => n.type === "function_definition");
    const byName = new Map<string, SyntaxNode[]>();
    for (const fn of functions) {
      const name = fn.childForFieldName("name")?.text;
      if (name) byName.set(name, [...(byName.get(name) ?? []), fn]);
    }

    // 1. What a helper does with its parameters: which of them reach a dangerous call (followed one call deep).
    const summaries = new Map<SyntaxNode, Summary>();
    for (const fn of functions) {
      checkBudgetNow();
      const parameters = parametersOf(fn).filter((p) => !["self", "cls"].includes(p.name));
      if (parameters.length === 0 || originsOf(fn).length > 0) continue; // a handler itself is checked below
      if (!/execute|system|popen|subprocess|eval|exec|pickle|yaml|open|requests|httpx|urlopen|redirect|HttpResponse|send_file|shutil|os\./.test(fn.text)) continue;
      const summary: Summary = { hits: new Map() };
      parameters.forEach((p, index) => {
        trackTaint(fn, new Set([p.name]), {
          onCall: (call, tainted) => {
            if (summary.hits.has(index)) return;
            for (const spec of sinksOf(call, text)) {
              if (spec.args.some((a) => carriedBy(a, tainted) !== undefined)) {
                summary.hits.set(index, { rule: spec.rule, line: call.startPosition.row + 1, spec });
                return;
              }
            }
          },
        });
      });
      if (summary.hits.size > 0) summaries.set(fn, summary);
    }

    const helperFor = (call: SyntaxNode, inside: SyntaxNode): { fn: SyntaxNode; summary: Summary } | undefined => {
      const callee = call.childForFieldName("function");
      const name = callee?.type === "identifier" ? callee.text : callee?.type === "attribute" && /^(?:self|cls)$/.test(callee.childForFieldName("object")?.text ?? "") ? callee.childForFieldName("attribute")?.text : undefined;
      if (!name) return undefined;
      const candidates = byName.get(name) ?? [];
      if (candidates.length !== 1) return undefined;
      const fn = candidates[0] as SyntaxNode;
      const summary = summaries.get(fn);
      return summary && fn.id !== inside.id ? { fn, summary } : undefined;
    };

    // 2. The data flow, function by function.
    for (const fn of functions) {
      checkBudgetNow();
      const origins = originsOf(fn);
      const originNames = new Set(origins.map((o) => o.name));
      const decorators = decoratorsOf(fn);
      const isRoute = decorators.some((d) => /^@[\w.]+\.(?:route|get|post|put|delete|patch|api_route)\s*\(/.test(d));
      if (origins.length === 0 && !/request\b/.test(fn.text)) continue; // nothing of the caller's in this function
      const redirectGuarded = /url_has_allowed_host_and_scheme|is_safe_url|is_safe_redirect|safe_redirect|allowed_hosts|\.startswith\(\s*["']\/["']\s*\)/.test(fn.text);

      trackTaint(fn, originNames, {
        onCall: (call, tainted) => {
          for (const spec of sinksOf(call, text)) {
            if (spec.rule === "open-redirect" && redirectGuarded) continue;
            for (const arg of spec.args) {
              const via = carriedBy(arg, tainted);
              if (via === undefined) continue;
              add({
                ruleId: spec.rule,
                severity: spec.severity,
                confidence: spec.confidence,
                message: spec.message(via),
                location: toLocation(call, filePath),
                sourceSnippet: via,
                sinkSnippet: snippet(call, text),
              });
              break;
            }
          }
          const helper = helperFor(call, fn);
          if (helper) {
            const { positional } = callArguments(call);
            const offset = parametersOf(helper.fn).some((p) => p.name === "self" || p.name === "cls") ? 1 : 0;
            for (const [index, hit] of helper.summary.hits) {
              const arg = positional[index - offset];
              const via = arg ? carriedBy(arg, tainted) : undefined;
              if (via === undefined) continue;
              const name = calleeText(call);
              add({
                ruleId: hit.rule,
                severity: hit.spec.severity,
                confidence: hit.spec.confidence,
                message: `${hit.spec.message(via)} The value is passed to ${name}() and reaches the vulnerable call at line ${hit.line}.`,
                location: toLocation(call, filePath),
                sourceSnippet: via,
                sinkSnippet: snippet(call, text),
              });
            }
          }
        },
        onReturn: (statement, tainted) => {
          if (!isRoute) return;
          const value = statement.namedChild(0);
          if (!value || !HTML_IN_STRING.test(value.text)) return;
          const via = carriedBy(value, tainted);
          if (via === undefined) return;
          add({
            ruleId: "xss",
            severity: "high",
            confidence: "medium",
            message: XSS_RETURN_MESSAGE(via),
            location: toLocation(statement, filePath),
            sourceSnippet: via,
            sinkSnippet: snippet(statement, text),
          });
        },
      });
    }

    // 3. Checks that need no data flow.
    for (const call of findNodes(root, (n) => n.type === "call")) {
      const name = calleeText(call);
      const { keywords, positional } = callArguments(call);
      if (/(?:^|\.)run$/.test(name) && keywords.get("debug")?.text === "True") {
        add({
          ruleId: "debug-mode",
          severity: "high",
          confidence: "high",
          message:
            "The development server runs with debug=True. Flask's debugger lets anyone who can reach the server run Python code from the error page (Werkzeug console), and errors show your source and settings. " +
            "Turn it on only locally, from an environment variable (debug=os.environ.get(\"FLASK_DEBUG\") == \"1\"), and serve production with gunicorn / uvicorn.",
          location: toLocation(call, filePath),
          sourceSnippet: "debug=True",
          sinkSnippet: snippet(call, text),
        });
      }
      if (/^(?:jwt|pyjwt|jose\.jwt|jwt\.api_jwt)\.decode$/.test(name) || name === "decode_jwt") {
        const options = keywords.get("options")?.text ?? "";
        const algorithms = keywords.get("algorithms")?.text ?? positional[2]?.text ?? "";
        if (/verify_signature["']?\s*:\s*False/.test(options) || keywords.get("verify")?.text === "False" || /["']none["']/i.test(algorithms)) {
          add({
            ruleId: "insecure-jwt",
            severity: "critical",
            confidence: "high",
            message: "The JWT is decoded without checking its signature (verify=False / verify_signature: False / the \"none\" algorithm). Anyone can forge a token with any user id or role. Decode with the secret and an explicit algorithms=[\"HS256\"] list.",
            location: toLocation(call, filePath),
            sourceSnippet: "unsigned tokens accepted",
            sinkSnippet: snippet(call, text),
          });
        }
      }
    }
    for (const fn of functions) {
      if (decoratorsOf(fn).some((d) => /^@(?:\w+\.)*csrf_exempt\b/.test(d))) {
        add({
          ruleId: "csrf",
          severity: "medium",
          confidence: "medium",
          message:
            `\`${fn.childForFieldName("name")?.text ?? "this view"}\` is marked @csrf_exempt: Django's CSRF protection is switched off for it. If it changes data for a signed-in browser session, another site can make the browser send the request. ` +
            `Remove the decorator and send the CSRF token (or use token authentication, which a browser does not attach by itself).`,
          location: toLocation(fn, filePath),
          sourceSnippet: "@csrf_exempt",
          sinkSnippet: snippet(fn.parent?.type === "decorated_definition" ? (fn.parent.namedChildren.find((c) => c.type === "decorator") ?? fn) : fn, text),
        });
      }
    }
    // `settings/dev.py`, `local_settings.py`, `tests/settings.py`: debug mode is what those files are for (judged by the file's own name and
    // the two folders above it: a project that lives in a folder called `test` is not a test settings file)
    const developmentFile = DEVELOPMENT_FILE.test(filePath.split(/[/\\]/).slice(-3).join("/"));
    for (const assignment of findNodes(root, (n) => n.type === "assignment")) {
      const left = assignment.childForFieldName("left");
      const right = assignment.childForFieldName("right");
      if (!developmentFile && left?.type === "identifier" && /^DEBUG$/.test(left.text) && right?.text === "True" && !/os\.environ|getenv|env\(/.test(assignment.text)) {
        add({
          ruleId: "debug-mode",
          severity: "high",
          confidence: "medium",
          message: "DEBUG = True: Django shows detailed error pages with your settings, source and SQL to anyone, and keeps every query in memory. Read it from the environment (DEBUG = os.environ.get(\"DEBUG\") == \"1\") so production runs with False.",
          location: toLocation(assignment, filePath),
          sourceSnippet: "DEBUG = True",
          sinkSnippet: snippet(assignment, text),
        });
      }
    }

    // 4. Secrets written in the code. (Seed data, fixtures and mocks hold made-up credentials on purpose: judged by name they are noise.)
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
    for (const literal of findNodes(root, (n) => n.type === "string")) {
      const value = strippedString(literal);
      const rawName = value === undefined ? undefined : assignedName(literal);
      if (value === undefined || !rawName || value.length < 4) continue;
      const name = normalizeName(rawName);
      if (isPlaceholder(value) || fixtureLike) continue;
      const signing = isSigningSecretName(name);
      if (!signing && !(isSensitiveName(name) && looksLikeSecret(value, name))) continue;
      if (signing && !looksLikeSecret(value, name) && !/^django-insecure-/.test(value) && value.length < 8) continue;
      add({
        ruleId: "hardcoded-secret",
        severity: "high",
        confidence: signing ? "high" : "medium",
        message: signing
          ? `\`${rawName}\` is a string written in the code (${redact(value)}) and is used to sign sessions or tokens. Anyone who reads the code can forge logins. Use a long random value from an environment variable (os.environ["${name.toUpperCase()}"]).`
          : `\`${rawName}\` is assigned a string that looks like a real credential (${redact(value)}). ${ROTATE}`,
        location: toLocation(literal, filePath),
        sourceSnippet: redact(value),
        sinkSnippet: (lines[literal.startPosition.row] ?? "").split(value).join("<redacted>").trim().slice(0, 160),
      });
    }
    return findings;
  }
}
