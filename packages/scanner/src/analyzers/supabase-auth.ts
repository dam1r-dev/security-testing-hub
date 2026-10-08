import { ParsedFile } from "../parsers/ast-parser";
import { findNodes, snippet, toLocation, SyntaxNode } from "../parsers/utils";
import { Finding } from "../types";
import { Analyzer } from "./base-analyzer";

/**
 * Two ways Supabase auth is misused in server code, both documented by Supabase itself:
 *
 *  1. `supabase.auth.getSession()` on the server trusts the session cookie as-is: nothing checks it with
 *     Supabase's auth server, so a forged or stale cookie passes. `getUser()` does the check.
 *  2. Deciding access from `user_metadata` (`user.user_metadata.role === "admin"`): users can rewrite their
 *     own user_metadata from the browser, so any user can make themselves an admin. `app_metadata` can only
 *     be written by the server.
 *
 * Client components ("use client") are skipped: a check in the browser is not an access control anyway.
 */

const USE_CLIENT = /^(?:\s*(?:\/\/[^\n]*\n|\/\*[\s\S]*?\*\/))*\s*["']use client["']/;
const GET_SESSION_CALLEE = /\.auth\.getSession$/;
const ROLE_LIKE_METADATA = /user_metadata\??(?:\.|\[["'])(role|roles|is_?admin|admin|plan|tier|permissions?|subscription\w*|access\w*)(?:["']\])?$/;

export class SupabaseAuthAnalyzer implements Analyzer {
  analyze(parsed: ParsedFile, filePath: string): Finding[] {
    const text = parsed.sourceCode;
    if (!/supabase/i.test(text) || USE_CLIENT.test(text)) return [];
    const root = parsed.tree.rootNode;
    const findings: Finding[] = [];
    const verifiesUser = /\.auth\.getUser\s*\(/.test(text);

    if (!verifiesUser) {
      for (const call of findNodes(root, (n) => n.type === "call_expression")) {
        const callee = call.childForFieldName("function");
        if (callee && GET_SESSION_CALLEE.test(callee.text)) findings.push(this.sessionFinding(call, filePath, text));
      }
    }

    const seen = new Set<string>();
    for (const member of findNodes(root, (n) => n.type === "member_expression" || n.type === "subscript_expression")) {
      if (!ROLE_LIKE_METADATA.test(member.text)) continue;
      const key = `${member.startIndex}`;
      if (seen.has(key)) continue;
      seen.add(key);
      findings.push({
        ruleId: "supabase-auth",
        severity: "high",
        confidence: "medium",
        message:
          `\`${member.text}\` reads a role or permission from user_metadata. Users can change their own user_metadata from the browser ` +
          `(supabase.auth.updateUser({ data: ... })), so any user can give themselves this value. Decide access from app_metadata ` +
          `(only the server can write it) or from a roles table you control.`,
        location: toLocation(member, filePath),
        sourceSnippet: member.text,
        sinkSnippet: snippet(member.parent ?? member, text),
      });
    }
    return findings;
  }

  private sessionFinding(call: SyntaxNode, filePath: string, text: string): Finding {
    return {
      ruleId: "supabase-auth",
      severity: "medium",
      confidence: "medium",
      message:
        "supabase.auth.getSession() on the server returns the session from the cookie without verifying it with Supabase's auth server, " +
        "so a forged or tampered cookie is accepted. Supabase's own docs say never to trust it for authorization on the server: " +
        "call supabase.auth.getUser() (it re-validates the token) and use the user it returns.",
      location: toLocation(call, filePath),
      sourceSnippet: "getSession() on the server",
      sinkSnippet: snippet(call, text),
    };
  }
}
