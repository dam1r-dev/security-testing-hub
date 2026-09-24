import * as fs from "fs";
import * as path from "path";
import { SyntaxNode, findNodes } from "../parsers/utils";

// Next.js App Router convention: a file literally named route.ts/tsx/js/jsx
// under an `app/` (or `src/app/`) directory defines an API route. This name
// is specific enough on its own (nobody else names a file exactly "route.ts")
// that requiring it to also sit under an `app/` folder isn't necessary.
const ROUTE_FILE_BASENAME_PATTERN = /^route\.(ts|tsx|js|jsx)$/;

const HTTP_METHOD_NAMES = new Set(["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]);
export const STATE_CHANGING_METHOD_NAMES = new Set(["POST", "PUT", "DELETE", "PATCH"]);

export function isNextRouteFile(filePath: string): boolean {
  return ROUTE_FILE_BASENAME_PATTERN.test(path.basename(filePath));
}

export interface NextHandler {
  method: string;
  node: SyntaxNode; // the function_declaration node (the whole handler)
}

function isExportedHttpMethodFunction(node: SyntaxNode): node is SyntaxNode {
  if (node.type !== "function_declaration") return false;
  const name = node.childForFieldName("name");
  if (!name || !HTTP_METHOD_NAMES.has(name.text)) return false;
  const parent = node.parent;
  // `export async function GET(...) {}` / `export function GET(...) {}`
  return !!parent && (parent.type === "export_statement" || parent.type === "program");
}

/** Finds every exported GET/POST/PUT/.../OPTIONS handler in a route.ts file. */
export function findNextHandlers(root: SyntaxNode): NextHandler[] {
  return findNodes(root, isExportedHttpMethodFunction).map((node) => ({
    method: (node.childForFieldName("name") as SyntaxNode).text,
    node,
  }));
}

/**
 * Turns a route.ts file's path into its App Router URL segments, e.g.
 * `app/api/accounts/[accountId]/route.ts` -> ["api", "accounts", "[accountId]"].
 * Route groups like `(admin)` are kept as-is (see isSensitiveSegment) even
 * though Next.js strips them from the real URL — a `(admin)` group folder is
 * a strong signal of intent even though it's invisible to visitors.
 */
export function routeSegments(filePath: string): string[] {
  const normalized = filePath.replace(/\\/g, "/");
  const appMatch = /(^|\/)(?:src\/)?app\//.exec(normalized);
  const afterApp = appMatch ? normalized.slice(appMatch.index + appMatch[0].length) : normalized;
  const withoutFile = afterApp.replace(/\/route\.(ts|tsx|js|jsx)$/, "");
  return withoutFile.split("/").filter(Boolean);
}

function bareSegmentName(segment: string): string {
  // Strips [, ], (, ), and a leading ... (catch-all) to get the bare name:
  // "[accountId]" -> "accountId", "(admin)" -> "admin", "[...slug]" -> "slug".
  return segment.replace(/^[[(]+/, "").replace(/[\])]+$/, "").replace(/^\.\.\./, "");
}

const ID_LIKE_PATTERN = /id$/i;

/** Dynamic (non-catch-all) segments whose name looks like a record id, e.g. `[accountId]`. */
export function idLikeDynamicSegments(segments: string[]): string[] {
  return segments
    .filter((s) => /^\[[^.\][]+\]$/.test(s)) // "[name]", not "[...slug]" or "[[...opt]]"
    .map(bareSegmentName)
    .filter((name) => ID_LIKE_PATTERN.test(name));
}

const SENSITIVE_SEGMENT_PATTERN = /^(admin|internal|manage|management|dashboard|debug|superuser|root)$/i;

/** True if any path segment (including route groups like `(admin)`) looks privileged. */
export function hasSensitiveSegment(segments: string[]): boolean {
  return segments.some((s) => SENSITIVE_SEGMENT_PATTERN.test(bareSegmentName(s)));
}

const MIDDLEWARE_FILENAMES = ["middleware.ts", "middleware.js", "middleware.mts", "middleware.mjs"];
const AUTH_HINT_IN_MIDDLEWARE =
  /(isAuthenticated|requireAuth|requireAdmin|requireRole|ensureAuth|ensureLoggedIn|authMiddleware|checkRole|checkAuth|isAdmin|hasRole|hasPermission|getServerSession|getToken|auth\(\)|withAuth|jwt\.verify|verifyToken)/i;

/**
 * Next.js commonly enforces auth centrally in a single project-root
 * middleware.ts (matched by URL via its `config.matcher`), not per route
 * file — so a route.ts with no local auth check isn't necessarily
 * unprotected. This walks up from the route file toward the filesystem
 * root looking for a middleware.ts/js next to (or above) the `app/`
 * directory, and treats one that mentions an auth-ish identifier as
 * evidence the route MIGHT be covered. It can't verify the matcher
 * actually covers this specific route (that requires evaluating Next.js's
 * matcher syntax against this path, out of scope for a v1 heuristic) — so
 * this errs toward fewer false positives at the cost of some false
 * negatives when middleware.ts exists but doesn't actually cover this route.
 */
export function hasNearbyMiddlewareWithAuthHint(filePath: string): boolean {
  let dir = path.dirname(path.resolve(filePath));

  for (let depth = 0; depth < 8; depth++) {
    for (const name of MIDDLEWARE_FILENAMES) {
      const candidate = path.join(dir, name);
      if (!fs.existsSync(candidate)) continue;
      try {
        if (AUTH_HINT_IN_MIDDLEWARE.test(fs.readFileSync(candidate, "utf8"))) return true;
      } catch {
        // Unreadable middleware file — keep searching rather than fail the scan.
      }
    }

    // Stop once we've checked the project root (package.json) — no point
    // searching further up into the user's filesystem.
    if (fs.existsSync(path.join(dir, "package.json"))) break;

    const parent = path.dirname(dir);
    if (parent === dir) break; // reached the filesystem root
    dir = parent;
  }

  return false;
}
