import { ParsedFile } from "../parsers/ast-parser";
import { findNodes, snippet, toLocation, SyntaxNode } from "../parsers/utils";
import { Finding } from "../types";
import { Analyzer } from "./base-analyzer";

// req.body.isAdmin, req.query.role, req.cookies.admin, req.headers['x-role'], ...
const ROLE_SOURCE_PATTERN =
  /^req\.(body|query|cookies|headers)(\.|\[)['"]?[\w-]*?(admin|role|permission|isadmin|is_admin|access[-_]?level|privilege)['"]?\]?/i;

function isRoleSource(node: SyntaxNode): boolean {
  if (node.type !== "member_expression" && node.type !== "subscript_expression") return false;
  return ROLE_SOURCE_PATTERN.test(node.text);
}

/**
 * Flags any read of a role/admin/permission-looking field straight from
 * client-controlled input (body, query, cookies, headers). Unlike the taint
 * rules, this doesn't need a "sink" — trusting the client to say what role
 * it has is the bug, regardless of where the value ends up. A user can set
 * `Admin=true` in a cookie/body/query param they fully control.
 */
export class InsecureRoleAssignmentAnalyzer implements Analyzer {
  analyze(parsed: ParsedFile, filePath: string): Finding[] {
    const matches = findNodes(parsed.tree.rootNode, isRoleSource);

    // A short expression like `req.body.role` can also match as a substring
    // match inside a longer enclosing member_expression; dedupe by location.
    const seen = new Set<string>();

    return matches
      .filter((node) => {
        const key = `${node.startIndex}:${node.endIndex}`;
        if (seen.has(key)) return false;
        seen.add(key);
        return true;
      })
      .map((node) => ({
        ruleId: "insecure-role-assignment" as const,
        severity: "critical" as const,
        confidence: "medium" as const,
        message:
          `'${node.text}' reads a role/permission field directly from client-controlled input. ` +
          "A user fully controls request body/query/cookies/headers, so they can set this to any value " +
          "(e.g. Admin=true). Look up the user's role server-side (session/database), never trust it from the request.",
        location: toLocation(node, filePath),
        sourceSnippet: snippet(node, parsed.sourceCode),
        sinkSnippet: snippet(node, parsed.sourceCode),
      }));
  }
}
