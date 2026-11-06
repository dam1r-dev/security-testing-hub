import { checkBudgetNow } from "../budget";
import { ParsedFile, SupportedLanguage } from "../parsers/ast-parser";
import { findNodes, snippet, toLocation } from "../parsers/utils";
import { Finding } from "../types";
import { Analyzer } from "../analyzers/base-analyzer";
import { ProjectContext } from "../taint/project";
import { callArguments, carriedBy, hasRoots, rootsOf, trackTaint } from "./engine";
import { GoProject } from "./project";
import { hardeningFindings, secretFindings } from "./hardening";
import { sinksOf } from "./sinks";

/**
 * The Go rules (net/http, gin, echo, fiber, chi, gorilla/mux, httprouter) in one analyzer: data flow from the request into SQL, OS
 * commands, file paths, outgoing requests, redirects, HTML and templates (engine.ts, sinks.ts), plus the checks that need no data
 * flow (hardening.ts): weak crypto, certificate checks switched off, login cookies, pprof, unsigned JWTs, CORS, secrets in the code.
 *
 * A value handed to a helper declared elsewhere in the project (`repo.FindUser(name)`) is followed (project.ts) when the name is
 * unambiguous. Not followed (yet): values stored in a struct field and read back in another function, interfaces with several
 * implementations, stored XSS through templates.
 */

const DEVELOPMENT_FILE = /(?:^|[/\\_.-])(?:dev|develop|development|local|test|tests|testing|ci|debug)(?:[/\\_.-]|$)/i;

// The function checks where the path ends up (a base name only, a prefix check on the cleaned path, a root-confined filesystem).
const PATH_GUARD = /filepath\.Base\(|path\.Base\(|securejoin|filepath\.Rel\(|os\.OpenRoot|fs\.ValidPath|http\.FileServer\(|strings\.Contains\([^)]*"\.\."|strings\.HasPrefix\([^)]*(?:Clean|Abs|base|root|dir|Dir)/;
// A redirect target is checked against a host list or a path prefix.
const REDIRECT_GUARD = /strings\.HasPrefix\([^)]*"\/"|\.Hostname\(\)\s*[!=]=|\.Host\s*[!=]=|allowedHosts|allowedOrigins|isSafeRedirect|safeRedirect|validRedirect|isAllowedURL|trusted\w*|allow-?list|white-?list/i;
// The response is declared as something that is not HTML.
const NOT_HTML = /Content-Type["'`,\s]+(?:application\/json|text\/plain|application\/octet-stream|text\/csv|image\/)/i;

// A redirect target taken from the request line starts with "/" (a path): it can only be turned into `//host` by a crafted request.
const PATH_DERIVED = /RequestURI|URL\.Path|EscapedPath|RawPath|\.Host\b/;

/** How sure a finding is, given what the function does around it. */
function confidenceFor(rule: string, base: Finding["confidence"], via: string, fnText: string): Finding["confidence"] {
  if (rule === "open-redirect" && PATH_DERIVED.test(via)) return "low";
  // reflecting the Origin is harmless for answers that carry no cookies: the dangerous pair is with Allow-Credentials
  if (rule === "insecure-cors" && !/Access-Control-Allow-Credentials|AllowCredentials/i.test(fnText)) return "low";
  return base;
}

export class GoAnalyzer implements Analyzer {
  readonly languages: readonly SupportedLanguage[] = ["go"];

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

    const functions = findNodes(root, (n) => n.type === "function_declaration" || n.type === "method_declaration" || n.type === "func_literal");
    const project = GoProject.of(context ?? ProjectContext.forSingleFile(filePath, parsed));
    project.parse(filePath, parsed);

    // 1. The data flow, function by function (only functions that receive a request or a framework context).
    for (const fn of functions) {
      const roots = rootsOf(fn);
      if (!hasRoots(roots)) continue;
      checkBudgetNow();
      const fnText = fn.text;
      const pathGuarded = PATH_GUARD.test(fnText);
      const redirectGuarded = REDIRECT_GUARD.test(fnText);
      const notHtml = NOT_HTML.test(fnText);
      trackTaint(fn, roots, new Set(), {
        onCall: (call, tainted, pathOnly) => {
          // the request line is a path: it cannot choose the host of an outgoing request
          const beyondPath = pathOnly.size > 0 ? new Set([...tainted].filter((n) => !pathOnly.has(n))) : tainted;
          for (const spec of sinksOf(call, roots)) {
            if (spec.rule === "path-traversal" && pathGuarded) continue;
            if (spec.rule === "open-redirect" && redirectGuarded) continue;
            if (spec.rule === "xss" && notHtml && !/^template\./.test(call.childForFieldName("function")?.text ?? "")) continue;
            for (const arg of spec.args) {
              const via = spec.rule === "ssrf" ? carriedBy(arg, beyondPath, roots, true) : carriedBy(arg, tainted, roots);
              if (via === undefined) continue;
              add({
                ruleId: spec.rule,
                severity: spec.severity,
                confidence: confidenceFor(spec.rule, spec.confidence, via, fnText),
                message: spec.message(via),
                location: toLocation(call, filePath),
                sourceSnippet: via,
                sinkSnippet: snippet(call, text),
              });
              break;
            }
          }
          // A value handed to a helper that builds the query, runs the command, opens the file...
          const helper = project.resolve(call, filePath);
          if (helper) {
            const args = callArguments(call);
            for (const [index, hit] of project.summary(helper)) {
              const arg = args[index];
              const via = arg ? (hit.spec.rule === "ssrf" ? carriedBy(arg, beyondPath, roots, true) : carriedBy(arg, tainted, roots)) : undefined;
              if (via === undefined) continue;
              if (hit.spec.rule === "path-traversal" && pathGuarded) continue;
              if (hit.spec.rule === "open-redirect" && redirectGuarded) continue;
              const place = hit.file === filePath ? `line ${hit.line}` : `${project.context.displayPath(hit.file)}:${hit.line}`;
              const route = hit.chain.length > 0 ? ` (via ${hit.chain.join(" -> ")})` : "";
              add({
                ruleId: hit.spec.rule,
                severity: hit.spec.severity,
                confidence: "medium",
                message: `${hit.spec.message(via)} The value is passed to ${helper.name}() and reaches the vulnerable call at ${place}${route}.`,
                location: toLocation(call, filePath),
                sourceSnippet: via,
                sinkSnippet: snippet(call, text),
              });
            }
          }
        },
      });
    }

    // 2. Patterns that need no data flow, and secrets written in the code.
    const developmentFile = DEVELOPMENT_FILE.test(filePath.split(/[/\\]/).slice(-3).join("/"));
    for (const finding of hardeningFindings(root, text, filePath, developmentFile)) add(finding);
    for (const finding of secretFindings(root, text, filePath)) add(finding);
    return findings;
  }
}
