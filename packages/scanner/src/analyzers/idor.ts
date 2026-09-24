import { ParsedFile } from "../parsers/ast-parser";
import { findNodes, snippet, toLocation, SyntaxNode } from "../parsers/utils";
import { Finding } from "../types";
import { Analyzer } from "./base-analyzer";
import { findNextHandlers, idLikeDynamicSegments, isNextRouteFile, routeSegments } from "./nextjs-routes";

const ROUTER_OBJECT_PATTERN = /^(app|router)$/i;
const ROUTER_SUFFIX_PATTERN = /router$/i;
const HTTP_METHODS = new Set(["get", "post", "put", "delete", "patch"]);
// :id, :userId, :accountId, :orderId, ... — a route param whose name suggests
// it selects a specific record.
const ID_PARAM_PATTERN = /:([A-Za-z0-9_]*[Ii]d[A-Za-z0-9_]*)\b/;
// Any reference to the authenticated user/session in the handler is treated as
// evidence of an ownership check — Express's req.user/req.session, and common
// Next.js session helpers (NextAuth's getServerSession/auth(), Clerk's currentUser(), ...).
const OWNERSHIP_CHECK_HINT =
  /req\.(user|session|auth|currentUser)\b|getServerSession|currentUser\s*\(|auth\s*\(\)|session\??\.\w*user/;

interface RouteRegistration {
  call: SyntaxNode;
  pathArg: SyntaxNode;
  paramName: string;
}

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

function findIdParamRoutes(root: SyntaxNode): RouteRegistration[] {
  const routes: RouteRegistration[] = [];
  for (const call of findNodes(root, isRouteRegistration)) {
    const args = call.childForFieldName("arguments");
    const pathArg = args?.namedChild(0);
    if (!pathArg || pathArg.type !== "string") continue;
    const match = ID_PARAM_PATTERN.exec(pathArg.text);
    if (!match) continue;
    routes.push({ call, pathArg, paramName: match[1] as string });
  }
  return routes;
}

/**
 * Heuristic Insecure Direct Object Reference (IDOR) check: a route whose path
 * takes an id-like param (`:id`, `:userId`, `:orderId`, ...) with no visible
 * ownership check (`req.user`, `req.session`, ...) anywhere in the handler.
 *
 * This can't tell whether the id is "unpredictable" (a GUID vs. a sequential
 * int) — both shapes get flagged the same way, since the underlying bug
 * (missing per-object authorization) is identical either way; unpredictable
 * IDs just make the attack slower to find manually, not impossible.
 */
export class IdorAnalyzer implements Analyzer {
  analyze(parsed: ParsedFile, filePath: string): Finding[] {
    if (isNextRouteFile(filePath)) return this.analyzeNextRoute(parsed, filePath);

    const routes = findIdParamRoutes(parsed.tree.rootNode);

    return routes
      .filter((route) => !OWNERSHIP_CHECK_HINT.test(route.call.text))
      .map((route) => ({
        ruleId: "idor" as const,
        severity: "high" as const,
        confidence: "low" as const,
        message:
          `Route takes an id-like param (':${route.paramName}') and looks up a record with it, but no ` +
          "ownership check (req.user/req.session/...) was found in the handler. Any authenticated user may " +
          "be able to read or modify another user's data by changing the id. Verify the requested record " +
          "belongs to the current user before returning/mutating it.",
        location: toLocation(route.call, filePath),
        sourceSnippet: `route param :${route.paramName}`,
        sinkSnippet: snippet(route.call, parsed.sourceCode),
      }));
  }

  /**
   * Next.js App Router: the id-like param comes from the FILE PATH (a
   * `[accountId]` folder), not a string in the code, so there's no single
   * "route registration" node to flag — each exported HTTP method handler
   * in the file is checked independently instead.
   */
  private analyzeNextRoute(parsed: ParsedFile, filePath: string): Finding[] {
    const idSegments = idLikeDynamicSegments(routeSegments(filePath));
    if (idSegments.length === 0) return [];

    const handlers = findNextHandlers(parsed.tree.rootNode);
    return handlers
      .filter((h) => !OWNERSHIP_CHECK_HINT.test(h.node.text))
      .map((h) => ({
        ruleId: "idor" as const,
        severity: "high" as const,
        confidence: "low" as const,
        message:
          `This route's path takes an id-like dynamic segment ('[${idSegments.join("]', '[")}]') and its ` +
          `${h.method} handler looks up a record, but no ownership check (session/auth) was found in it. ` +
          "Any authenticated user may be able to read or modify another user's data by changing the id in " +
          "the URL. Verify the requested record belongs to the current user before returning/mutating it.",
        location: toLocation(h.node, filePath),
        sourceSnippet: `dynamic segment [${idSegments.join("], [")}]`,
        sinkSnippet: snippet(h.node, parsed.sourceCode),
      }));
  }
}
