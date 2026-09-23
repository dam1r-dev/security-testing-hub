import { ParsedFile } from "../parsers/ast-parser";
import { findNodes, snippet, toLocation, SyntaxNode } from "../parsers/utils";
import { Finding } from "../types";
import { Analyzer } from "./base-analyzer";

const ROUTER_OBJECT_PATTERN = /^(app|router)$/i;
const ROUTER_SUFFIX_PATTERN = /router$/i;
const HTTP_METHODS = new Set(["get", "post", "put", "delete", "patch", "all", "use"]);
// Path segments that usually mean "privileged functionality lives here".
const SENSITIVE_PATH_PATTERN = /\/(admin|internal|manage|management|dashboard|debug|superuser|root)(\/|$|['"`])/i;
// Any of these appearing in the route registration is treated as evidence of
// an access-control check, whether it's real middleware or an inline check.
const AUTH_CHECK_HINT =
  /(isAuthenticated|requireAuth|requireAdmin|requireRole|ensureAuth|ensureLoggedIn|authMiddleware|checkRole|checkAuth|isAdmin|hasRole|hasPermission|passport|authorize|authorization|verifyToken|jwt\.verify|req\.user\.role|req\.session\.role)/i;

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
}
