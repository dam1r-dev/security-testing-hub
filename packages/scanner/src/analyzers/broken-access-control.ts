import { ParsedFile } from "../parsers/ast-parser";
import { findNodes, snippet, toLocation, SyntaxNode } from "../parsers/utils";
import { Finding } from "../types";
import { Analyzer } from "./base-analyzer";
import {
  findNextHandlers,
  hasNearbyMiddlewareWithAuthHint,
  hasSensitiveSegment,
  isNextRouteFile,
  routeSegments,
} from "./nextjs-routes";

const ROUTER_OBJECT_PATTERN = /^(app|router)$/i;
const ROUTER_SUFFIX_PATTERN = /router$/i;
const HTTP_METHODS = new Set(["get", "post", "put", "delete", "patch", "all", "use"]);
// Path segments that usually mean "privileged functionality lives here".
const SENSITIVE_PATH_PATTERN = /\/(admin|internal|manage|management|dashboard|debug|superuser|root)(\/|$|['"`])/i;
// Any of these appearing in the route registration is treated as evidence of
// an access-control check, whether it's real middleware or an inline check.
const AUTH_CHECK_HINT =
  /(isAuthenticated|requireAuth|requireAdmin|requireRole|ensureAuth|ensureLoggedIn|authMiddleware|checkRole|checkAuth|isAdmin|hasRole|hasPermission|passport|authorize|authorization|verifyToken|jwt\.verify|req\.user\.role|req\.session\.role|getServerSession|currentUser\s*\(|auth\s*\(\))/i;

function isRouteRegistration(node: SyntaxNode): boolean {
  if (node.type !== "call_expression") return false;
  const callee = node.childForFieldName("function");
  if (!callee || callee.type !== "member_expression") return false;
  const object = callee.childForFieldName("object");
  const property = callee.childForFieldName("property");
  if (!object || !property) return false;
  const objectLooksLikeRouter = ROUTER_OBJECT_PATTERN.test(object.text) || ROUTER_SUFFIX_PATTERN.test(object.text);
  return objectLooksLikeRouter && HTTP_METHODS.has(property.text.toLowerCase());
}

/**
 * Heuristic broken access control check: a route whose path looks like
 * privileged/admin functionality (`/admin`, `/internal`, `/manage`, ...) with
 * no visible auth/role check in its registration.
 *
 * "Security through obscurity" (an unguessable admin URL) doesn't change
 * anything here on purpose — a hidden-but-unchecked route is just as flagged
 * as an obvious one, because the URL being secret isn't a real access control.
 */
export class BrokenAccessControlAnalyzer implements Analyzer {
  analyze(parsed: ParsedFile, filePath: string): Finding[] {
    if (isNextRouteFile(filePath)) return this.analyzeNextRoute(parsed, filePath);

    const routes = findNodes(parsed.tree.rootNode, isRouteRegistration);

    return routes
      .filter((route) => {
        const args = route.childForFieldName("arguments");
        const pathArg = args?.namedChild(0);
        if (!pathArg || pathArg.type !== "string") return false;
        return SENSITIVE_PATH_PATTERN.test(pathArg.text);
      })
      .filter((route) => !AUTH_CHECK_HINT.test(route.text))
      .map((route) => ({
        ruleId: "broken-access-control" as const,
        severity: "critical" as const,
        confidence: "low" as const,
        message:
          "Route path looks like privileged/admin functionality, but no auth or role check was found in its " +
          "registration (no middleware or inline check matching things like isAuthenticated/requireAdmin/req.user.role). " +
          "A hidden or unguessable URL is not access control — verify the caller's role/permissions on the server " +
          "for every request to this route.",
        location: toLocation(route, filePath),
        sourceSnippet: "(no auth/role check found)",
        sinkSnippet: snippet(route, parsed.sourceCode),
      }));
  }

  /**
   * Next.js App Router: "the route path" is the file's own folder structure
   * (including route groups like `(admin)`, invisible in the real URL but a
   * strong signal of intent), and access control is often centralized in a
   * project-root middleware.ts rather than the route file itself — see
   * hasNearbyMiddlewareWithAuthHint for why we check for that before flagging.
   */
  private analyzeNextRoute(parsed: ParsedFile, filePath: string): Finding[] {
    if (!hasSensitiveSegment(routeSegments(filePath))) return [];
    if (hasNearbyMiddlewareWithAuthHint(filePath)) return [];

    return findNextHandlers(parsed.tree.rootNode)
      .filter((h) => !AUTH_CHECK_HINT.test(h.node.text))
      .map((h) => ({
        ruleId: "broken-access-control" as const,
        severity: "critical" as const,
        confidence: "low" as const,
        message:
          `This route's path looks like privileged/admin functionality, but its ${h.method} handler has no ` +
          "auth/role check, and no nearby middleware.ts appears to guard it either. A hidden or unguessable " +
          "URL is not access control — verify the caller's role/permissions on the server for every request here.",
        location: toLocation(h.node, filePath),
        sourceSnippet: "(no auth/role check found)",
        sinkSnippet: snippet(h.node, parsed.sourceCode),
      }));
  }
}
