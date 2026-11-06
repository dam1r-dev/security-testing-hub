import { checkBudgetNow } from "../budget";
import { ParsedFile, SupportedLanguage } from "../parsers/ast-parser";
import { findNodes, snippet, toLocation } from "../parsers/utils";
import { Finding } from "../types";
import { Analyzer } from "../analyzers/base-analyzer";
import { ProjectContext } from "../taint/project";
import { argumentsOf, callInfo, carriedBy, hasRoots, rootsOf, trackTaint } from "./engine";
import { JavaProject } from "./project";
import { hardeningFindings, secretFindings } from "./hardening";
import { XSS_MESSAGE, redirectTarget, sinksOf } from "./sinks";

/**
 * The Java rules (Servlets, Spring MVC / WebFlux, JAX-RS, Micronaut, Spark, Javalin) in one analyzer: data flow from the request into SQL
 * (JDBC, JdbcTemplate, JPA / Hibernate native queries), OS commands, file paths, outgoing requests, redirects, HTML, deserialization and
 * expression languages (engine.ts, sinks.ts), plus the checks that need no data flow (hardening.ts): weak crypto, certificate checks
 * switched off, login cookies, Spring Security (CSRF off, every route open), CORS, unsigned JWTs, XML external entities, secrets in the code.
 *
 * A value handed to a method declared elsewhere in the project (`userService.findByName(name)`) is followed (project.ts) when the name is
 * unambiguous. Not followed (yet): values stored in a field and read in another method, interfaces with several implementations, JSP /
 * Thymeleaf templates (stored XSS), MyBatis `${}` in XML mappers, Spring Data `@Query` strings.
 */

const DEVELOPMENT_FILE = /(?:^|[/\\_.-])(?:dev|develop|development|local|test|tests|testing|ci|debug)(?:[/\\_.-]|$)/i;

// The method checks where the path ends up (a canonical / normalized path compared with the base, a base name only).
const PATH_GUARD = /getCanonicalPath\(|\.normalize\(\)|FilenameUtils\.(?:getName|normalize)|getFileName\(\)|cleanPath\(|contains\("\.\."\)|toRealPath\(|isInside|isSubPath|\.startsWith\(\s*(?:base|root|dir|upload|safe)/i;
// A redirect target is checked against a host list or a path prefix.
const REDIRECT_GUARD = /startsWith\("\/"\)|\.getHost\(\)\s*(?:\)|\.equals|\.equalsIgnoreCase|\.endsWith|\.contains)|allowedHosts|allowedOrigins|isSafeRedirect|safeRedirect|validRedirect|isAllowedUrl|UrlValidator|trusted\w*|allow-?list|white-?list/i;
// The response is declared as something that is not HTML.
const NOT_HTML = /(?:setContentType|setHeader|contentType|type|header)\(\s*"(?:Content-Type"\s*,\s*")?(?:application\/json|text\/plain|application\/octet-stream|text\/csv|image\/|application\/xml|text\/xml)|produces\s*=\s*(?:\{\s*)?(?:MediaType\.APPLICATION_JSON|"application\/json|MediaType\.TEXT_PLAIN|"text\/plain)|APPLICATION_JSON|MediaType\.TEXT_PLAIN/i;
const HTML_IN_STRING = /"[^"]*<\s*[a-zA-Z!/][^"]*"/;
// A redirect target taken from the request line starts with "/" (a path): it can only be turned into `//host` by a crafted request.
const PATH_DERIVED = /getRequestURI|getRequestURL|getPathInfo|getServletPath|getQueryString|\.getHeader\("(?:Host|Referer|Origin)"\)/;

/** How sure a finding is, given what the method does around it. */
function confidenceFor(rule: string, base: Finding["confidence"], via: string, fnText: string): Finding["confidence"] {
  if (rule === "open-redirect" && PATH_DERIVED.test(via)) return "low";
  // reflecting the Origin is harmless for answers that carry no cookies: the dangerous pair is with Allow-Credentials
  if (rule === "insecure-cors" && !/Access-Control-Allow-Credentials|allowCredentials/i.test(fnText)) return "low";
  return base;
}

function classAnnotations(node: import("../parsers/utils").SyntaxNode): string {
  for (let p = node.parent; p; p = p.parent) {
    if (p.type === "class_declaration") return p.namedChildren.find((c) => c.type === "modifiers")?.text ?? "";
  }
  return "";
}

export class JavaAnalyzer implements Analyzer {
  readonly languages: readonly SupportedLanguage[] = ["java"];

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

    const methods = findNodes(root, (n) => n.type === "method_declaration" || n.type === "constructor_declaration" || n.type === "lambda_expression");
    const project = JavaProject.of(context ?? ProjectContext.forSingleFile(filePath, parsed));
    project.parse(filePath, parsed);

    // 1. The data flow, method by method (only methods that receive a request or values the framework fills from it).
    for (const fn of methods) {
      const found = rootsOf(fn, text);
      if (!hasRoots(found)) continue;
      const roots = { ...found, returns: (call: import("../parsers/utils").SyntaxNode) => project.returnParams(call, filePath) };
      checkBudgetNow();
      const fnText = fn.text;
      const pathGuarded = PATH_GUARD.test(fnText);
      const redirectGuarded = REDIRECT_GUARD.test(fnText);
      const notHtml = NOT_HTML.test(fnText) || NOT_HTML.test(fn.namedChildren.find((c) => c.type === "modifiers")?.text ?? "");
      const responseBody = /ResponseBody|RestController/.test(`${fn.namedChildren.find((c) => c.type === "modifiers")?.text ?? ""} ${classAnnotations(fn)}`);
      trackTaint(fn, roots, new Set(), text, {
        onCall: (call, tainted, pathOnly) => {
          // the request line is a path: it cannot choose the host of an outgoing request
          const beyondPath = pathOnly.size > 0 ? new Set([...tainted].filter((n) => !pathOnly.has(n))) : tainted;
          for (const spec of sinksOf(call, roots, fnText)) {
            if (spec.rule === "path-traversal" && pathGuarded) continue;
            if (spec.rule === "open-redirect" && redirectGuarded) continue;
            if (spec.rule === "xss" && notHtml) continue;
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
          // A value handed to a method that builds the query, runs the command, opens the file...
          const helper = project.resolve(call, filePath);
          if (helper) {
            const args = argumentsOf(call);
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
        onReturn: (statement, tainted) => {
          const value = statement.namedChild(0);
          if (!value) return;
          // Spring: return "redirect:" + url;  (a view name that starts with redirect: sends the visitor away)
          const prefix = /^(?:"redirect:|"forward:)/.test(value.text) ? (value.text.startsWith('"forward:') ? "forward:" : "redirect:") : "";
          if (prefix === "redirect:" && !redirectGuarded) {
            for (const arg of redirectTarget(value, prefix)) {
              const via = carriedBy(arg, tainted, roots);
              if (via === undefined) continue;
              add({
                ruleId: "open-redirect",
                severity: "medium",
                confidence: confidenceFor("open-redirect", "medium", via, fnText),
                message:
                  `User-controlled input ('${via}') decides where the visitor is sent ("redirect:" + value). A link on your site can then lead to a look-alike page that asks for the password. ` +
                  `Redirect only to a path of this site (it starts with a single "/", not "//"), or compare the parsed host against an allow-list.`,
                location: toLocation(statement, filePath),
                sourceSnippet: via,
                sinkSnippet: snippet(statement, text),
              });
            }
            return;
          }
          // A controller that returns HTML text built from the request: @ResponseBody / @RestController send it as it is.
          let body = value;
          if (value.type === "method_invocation" && /^ResponseEntity\b/.test(value.text)) {
            const info = callInfo(value);
            body = info?.args[0] ?? value;
          }
          if (!responseBody || notHtml || !HTML_IN_STRING.test(body.text)) return;
          const via = carriedBy(body, tainted, roots);
          if (via === undefined) return;
          add({
            ruleId: "xss",
            severity: "high",
            confidence: "medium",
            message: XSS_MESSAGE(via),
            location: toLocation(statement, filePath),
            sourceSnippet: via,
            sinkSnippet: snippet(statement, text),
          });
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
