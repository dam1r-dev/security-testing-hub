import { ParsedFile } from "../parsers/ast-parser";
import { findNodes, snippet, toLocation, SyntaxNode } from "../parsers/utils";
import { Finding } from "../types";
import { Analyzer } from "./base-analyzer";
import { findNextHandlers, idLikeDynamicSegments, isNextRouteFile, routeSegments } from "./nextjs-routes";
import { authKind } from "./project-info";
import { FileInfo, ProjectContext } from "../taint/project";

const ROUTER_OBJECT_PATTERN = /^(app|router)$/i;
const ROUTER_SUFFIX_PATTERN = /router$/i;
const HTTP_METHODS = new Set(["get", "post", "put", "delete", "patch"]);
// :id, :userId, :user_id, :accountID, ... — a route param whose NAME IS an id.
// (A plain "contains id" test also matched :provider, :video, :guide, ... —
// seen in practice on a real project, so the name has to END in Id/ID/_id.)
const ID_PARAM_PATTERN = /:((?:[A-Za-z0-9_]*(?:Id|ID|_id))|id)(?![A-Za-z0-9_])/;
// Any reference to the authenticated user/session in the handler is treated as
// evidence of an ownership check — Express's req.user/req.session, and common
// Next.js session helpers (NextAuth's getServerSession/auth(), Clerk's currentUser(), ...).
//
// Also by NAME: projects wrap the check in a helper (`verifyCurrentUserHasAccessToPost(id)`,
// `security.appendUserId()`, `checkOwnership(...)`), and a route that a "deny" middleware switches
// off (`security.denyAll()`) has no object to reach at all.
export const OWNERSHIP_CHECK_HINT = new RegExp(
  [
    String.raw`req\.(user|session|auth|currentUser)\b`,
    "getServerSession",
    String.raw`currentUser\s*\(`,
    String.raw`auth\s*\(\)`,
    String.raw`session\??\.\w*user`,
    // a call (`verifyAccess(id)`) or a middleware reference (`app.get("/x/:id", checkOwnership, handler)`)
    String.raw`\b\w*(verify|check|assert|ensure|require|authori[sz]e|validate)\w*(Access|Owner|Ownership|Permission|Permissions|Allowed|Authori[sz]ation)\w*\b`,
    String.raw`\b(isOwner|belongsTo|userOwns|ownsResource)\s*\(`,
    String.raw`\bappend\w*(UserId|Owner)\w*\s*\(`,
    String.raw`\b(deny\w*|forbid\w*|reject\w*|disable\w*|notAllowed|blockAll)\s*\(`,
  ].join("|"),
  "i",
);

// A route behind an explicit role check (`checkRole(['Admin'])`, `authorize('ADMIN')`, `requireAdmin`) is gated by
// the developer's own authorization model; whether a role may see every record of a table (a catalogue, an admin
// screen) or only its own is a design decision this rule cannot read from the code.
const ROLE_GATE = /\b(?:checkRole|requireRole|hasRole|authorizeRoles?|restrictTo|allowRoles?|permit|requirePermission|hasPermission|authorize)\s*\(\s*\[?\s*['"`]|\b(?:requireAdmin|isAdmin|adminOnly|onlyAdmin)\b/;

/** True when this code, or a project function it calls (two levels deep), looks at who the caller is. */
function checksOwnership(node: SyntaxNode, info: FileInfo, project: ProjectContext, depth: number): boolean {
  if (OWNERSHIP_CHECK_HINT.test(node.text)) return true;
  if (depth <= 0) return false;
  for (const call of info.callsIn(node)) {
    const fn = project.resolveCallee(call, info);
    if (fn && checksOwnership(fn.node, fn.info, project, depth - 1)) return true;
  }
  return false;
}

/** Route handlers given by name (`Controller.getUser`) live in another file; follow them there. */
function handlerChecksOwnership(route: SyntaxNode, info: FileInfo, project: ProjectContext): boolean {
  const args = route.childForFieldName("arguments");
  for (let i = 1; args && i < args.namedChildCount; i++) {
    const arg = args.namedChild(i);
    if (!arg) continue;
    if (arg.type === "identifier" || arg.type === "member_expression") {
      const entity = project.resolve(arg.type === "identifier" ? info.lookup(arg.text, route) : info.entityFromExpr(arg));
      if (entity?.kind === "fn" && checksOwnership(entity.fn.node, entity.fn.info, project, 2)) return true;
    } else if (checksOwnership(arg, info, project, 2)) {
      return true;
    }
  }
  return false;
}

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
  analyze(parsed: ParsedFile, filePath: string, context?: ProjectContext): Finding[] {
    // No authentication library anywhere in the project: there is no per-user data to be reached through
    // someone else's id (a demo or public API). Admin-looking routes are still covered by broken-access-control.
    if (authKind(filePath) === "none") return [];
    const project = context ?? ProjectContext.forSingleFile(filePath, parsed);
    const info = project.fileInfo(filePath, parsed);
    if (isNextRouteFile(filePath)) return this.analyzeNextRoute(parsed, filePath, project, info);

    const routes = findIdParamRoutes(parsed.tree.rootNode);

    return routes
      .filter((route) => !OWNERSHIP_CHECK_HINT.test(route.call.text) && !ROLE_GATE.test(route.call.text))
      .filter((route) => !info || !handlerChecksOwnership(route.call, info, project))
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
  private analyzeNextRoute(parsed: ParsedFile, filePath: string, project: ProjectContext, info: FileInfo | undefined): Finding[] {
    const idSegments = idLikeDynamicSegments(routeSegments(filePath));
    if (idSegments.length === 0) return [];

    const handlers = findNextHandlers(parsed.tree.rootNode);
    return handlers
      .filter((h) => (info ? !checksOwnership(h.node, info, project, 2) : !OWNERSHIP_CHECK_HINT.test(h.node.text)))
      .filter((h) => !ROLE_GATE.test(h.node.text))
      // A handler that takes no arguments cannot read the id from the URL at all.
      .filter((h) => (h.node.childForFieldName("parameters")?.namedChildCount ?? 1) > 0)
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
