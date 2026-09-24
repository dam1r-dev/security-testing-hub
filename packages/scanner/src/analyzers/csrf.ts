import { ParsedFile } from "../parsers/ast-parser";
import { findNodes, snippet, toLocation, SyntaxNode } from "../parsers/utils";
import { Finding } from "../types";
import { Analyzer } from "./base-analyzer";
import { findNextHandlers, isNextRouteFile, STATE_CHANGING_METHOD_NAMES } from "./nextjs-routes";

const STATE_CHANGING_METHODS = new Set(["post", "put", "delete", "patch"]);
const ROUTER_OBJECT_PATTERN = /^(app|router)$/i;
const ROUTER_SUFFIX_PATTERN = /router$/i;
// Any of these appearing anywhere in the file is treated as evidence that CSRF
// protection is wired up somewhere (global middleware, csurf, custom token check, ...).
const CSRF_PROTECTION_HINT = /csrf/i;

function isStateChangingRouteRegistration(node: SyntaxNode): boolean {
  if (node.type !== "call_expression") return false;
  const callee = node.childForFieldName("function");
  if (!callee || callee.type !== "member_expression") return false;
  const object = callee.childForFieldName("object");
  const property = callee.childForFieldName("property");
  if (!object || !property) return false;
  const objectLooksLikeRouter = ROUTER_OBJECT_PATTERN.test(object.text) || ROUTER_SUFFIX_PATTERN.test(object.text);
  return objectLooksLikeRouter && STATE_CHANGING_METHODS.has(property.text.toLowerCase());
}

/**
 * Heuristic CSRF check (not taint-based, unlike the other four analyzers):
 * flags state-changing Express routes (POST/PUT/DELETE/PATCH) in files that
 * show no sign of CSRF protection anywhere (csurf middleware, req.csrfToken(),
 * a custom "csrf" check, ...).
 *
 * This is file-scoped on purpose — CSRF middleware is usually registered once
 * with app.use(...) elsewhere in the file, not per-route, so per-route detection
 * would just re-derive the same false negative. Cookie-based auth (session
 * cookies) is assumed, since CSRF isn't exploitable against pure bearer-token APIs.
 *
 * Also covers Next.js App Router `route.ts` handlers — those are plain HTTP
 * endpoints with no built-in CSRF protection (unlike Server Actions, which
 * Next.js protects with an Origin-header check since v14; this rule doesn't
 * apply to those since they aren't route.ts files).
 */
export class CsrfAnalyzer implements Analyzer {
  analyze(parsed: ParsedFile, filePath: string): Finding[] {
    if (CSRF_PROTECTION_HINT.test(parsed.sourceCode)) return [];

    if (isNextRouteFile(filePath)) {
      return findNextHandlers(parsed.tree.rootNode)
        .filter((h) => STATE_CHANGING_METHOD_NAMES.has(h.method))
        .map((h) => this.toFinding(h.node, filePath, parsed.sourceCode));
    }

    const routes = findNodes(parsed.tree.rootNode, isStateChangingRouteRegistration);
    return routes.map((route) => this.toFinding(route, filePath, parsed.sourceCode));
  }

  private toFinding(node: SyntaxNode, filePath: string, sourceCode: string): Finding {
    return {
      ruleId: "csrf",
      severity: "medium",
      confidence: "low",
      message:
        "State-changing route (POST/PUT/DELETE/PATCH) found with no CSRF protection detected in this file " +
        "(no csurf middleware, req.csrfToken(), or similar). If this route relies on session cookies for " +
        "auth, add CSRF token verification; SameSite=strict cookies or a pure bearer-token API make this a non-issue.",
      location: toLocation(node, filePath),
      sourceSnippet: "(no CSRF token check found in file)",
      sinkSnippet: snippet(node, sourceCode),
    };
  }
}
