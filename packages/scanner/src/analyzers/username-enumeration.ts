import { ParsedFile } from "../parsers/ast-parser";
import { findFunctionBodies, findNodes, snippet, toLocation, SyntaxNode } from "../parsers/utils";
import { Finding } from "../types";
import { Analyzer } from "./base-analyzer";

// Error text that reveals "this username doesn't exist" vs. "the password is wrong" —
// two different messages let an attacker enumerate valid usernames.
const UNKNOWN_USER_HINT = /invalid.{0,15}user|unknown.{0,15}user|user.{0,15}not.{0,15}found|no.{0,15}such.{0,15}user/i;
const WRONG_PASSWORD_HINT = /invalid.{0,15}password|incorrect.{0,15}password|wrong.{0,15}password/i;
const LOGIN_CONTEXT_HINT = /login|signin|sign-in|authenticate|password/i;

function isStringLiteral(node: SyntaxNode): boolean {
  return node.type === "string" || node.type === "template_string";
}

/**
 * Heuristic check for username enumeration via different error messages: a
 * function that appears to handle login (references "login"/"password"/etc)
 * and contains two distinct string literals — one implying "no such user",
 * another implying "wrong password". Sending different responses for those
 * two cases lets an attacker enumerate valid usernames by brute-forcing.
 *
 * This is intentionally narrow (exact wording only) — it won't catch
 * differences in HTTP status code or response timing, which need dynamic
 * testing (see docs/attack-playbook.md).
 */
export class UsernameEnumerationAnalyzer implements Analyzer {
  analyze(parsed: ParsedFile, filePath: string): Finding[] {
    const root = parsed.tree.rootNode;
    const functionBodies = findFunctionBodies(root);
    const scopes = functionBodies.length > 0 ? functionBodies : [root];
    const findings: Finding[] = [];
    const seen = new Set<string>();

    for (const scope of scopes) {
      if (!LOGIN_CONTEXT_HINT.test(scope.text)) continue;

      const literals = findNodes(scope, isStringLiteral);
      const unknownUserLiteral = literals.find((n) => UNKNOWN_USER_HINT.test(n.text));
      const wrongPasswordLiteral = literals.find(
        (n) => WRONG_PASSWORD_HINT.test(n.text) && n.startIndex !== unknownUserLiteral?.startIndex,
      );
      if (!unknownUserLiteral || !wrongPasswordLiteral) continue;

      const key = `${unknownUserLiteral.startIndex}:${wrongPasswordLiteral.startIndex}`;
      if (seen.has(key)) continue;
      seen.add(key);

      findings.push({
        ruleId: "username-enumeration",
        severity: "medium",
        confidence: "low",
        message:
          `Found two distinct error messages for "unknown user" (${snippet(unknownUserLiteral, parsed.sourceCode)}) ` +
          `and "wrong password" (${snippet(wrongPasswordLiteral, parsed.sourceCode)}) in the same login handler. ` +
          "An attacker can tell these apart to enumerate valid usernames before brute-forcing passwords. " +
          "Use one identical message (e.g. \"Invalid username or password\") for both cases, and keep response " +
          "time/status code consistent too.",
        location: toLocation(wrongPasswordLiteral, filePath),
        sourceSnippet: snippet(unknownUserLiteral, parsed.sourceCode),
        sinkSnippet: snippet(wrongPasswordLiteral, parsed.sourceCode),
      });
    }

    return findings;
  }
}
