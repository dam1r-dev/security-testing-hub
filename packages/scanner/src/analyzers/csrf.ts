import { ParsedFile } from "../parsers/ast-parser";
import { findNodes, snippet, toLocation, SyntaxNode } from "../parsers/utils";
import { Finding } from "../types";
import { Analyzer } from "./base-analyzer";
import { findNextHandlers, isNextRouteFile, STATE_CHANGING_METHOD_NAMES } from "./nextjs-routes";
import { isBearerOnlyProject } from "./project-info";

const STATE_CHANGING_METHODS = new Set(["post", "put", "delete", "patch"]);
const ROUTER_OBJECT_PATTERN = /^(app|router)$/i;
const ROUTER_SUFFIX_PATTERN = /router$/i;
// Any of these appearing anywhere in the file is treated as evidence that CSRF
// protection is wired up somewhere (global middleware, csurf, custom token check, ...).
const CSRF_PROTECTION_HINT = /csrf/i;
// Webhooks (Stripe, GitHub, ...) are authenticated by a signature over the
// body, not by a browser cookie, so a forged cross-site request can't pass —
// CSRF doesn't apply, and flagging them is pure noise.
const WEBHOOK_HINT = /webhook|stripe-signature|x-hub-signature|x-slack-signature|svix-signature/i;

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
    // Pure bearer-token API (JWT in a header, no cookie/session library): the
    // browser never attaches the credential on its own, so CSRF can't happen.
    if (isBearerOnlyProject(filePath)) return [];

    const nodes = isNextRouteFile(filePath)
      ? findNextHandlers(parsed.tree.rootNode)
          .filter((h) => STATE_CHANGING_METHOD_NAMES.has(h.method))
          .map((h) => h.node)
      : findNodes(parsed.tree.rootNode, isStateChangingRouteRegistration);

    const exposed = nodes.filter((n) => !WEBHOOK_HINT.test(n.text) && !WEBHOOK_HINT.test(filePath));
    const first = exposed[0];
    if (!first) return [];

    // One finding per file, not per route: they all share a single root cause
    // (no anti-forgery protection wired up), and a 12-route controller
    // shouldn't read as 12 separate bugs or drag the score 12x.
    return [this.toFinding(first, exposed.length, filePath, parsed.sourceCode)];
  }

  private toFinding(node: SyntaxNode, routeCount: number, filePath: string, sourceCode: string): Finding {
    const scope = routeCount > 1 ? `${routeCount} state-changing routes (POST/PUT/DELETE/PATCH, first one shown)` : "State-changing route (POST/PUT/DELETE/PATCH)";
    return {
      ruleId: "csrf",
      severity: "medium",
      confidence: "low",
      message:
        `${scope} found with no CSRF protection detected in this file ` +
        "(no csurf middleware, req.csrfToken(), or similar). If these routes rely on session cookies for " +
        "auth, add CSRF token verification; SameSite=strict cookies or a pure bearer-token API make this a non-issue.",
      location: toLocation(node, filePath),
      sourceSnippet: "(no CSRF token check found in file)",
      sinkSnippet: snippet(node, sourceCode),
    };
  }
}
