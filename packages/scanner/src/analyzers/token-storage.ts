import { ParsedFile } from "../parsers/ast-parser";
import { SyntaxNode, findNodes, snippet, toLocation } from "../parsers/utils";
import { ProjectContext } from "../taint/project";
import { Finding } from "../types";
import { Analyzer } from "./base-analyzer";

/**
 * A login token kept where any script on the page can read it: `localStorage.setItem("token", jwt)`,
 * `sessionStorage.token = ...`, `document.cookie = "token=" + jwt`, `Cookies.set("token", jwt)` (a cookie written from
 * JavaScript cannot be HttpOnly). One cross-site-scripting hole, or one compromised npm package in the page, reads it
 * and the account is taken over. An HttpOnly cookie set by the server is invisible to scripts.
 */

// A key that names a credential. "auth" alone is not enough (`authMode`, `authTab` are UI state).
const SECRET_KEY = /token|jwt|bearer|secret|session[_-]?id|api[_-]?key|credential|password|passwd/i;
// Not credentials despite the word: a flag that says whether a token exists, a CSRF token that is meant for scripts.
const BENIGN_KEY = /csrf|xsrf|has[_-]?token|token[_-]?(?:type|count|expires?|expiry|exp|present|valid)|\bis[_-]?(?:logged|auth)/i;

const STORAGE = /^(?:window\.)?(?:localStorage|sessionStorage)$/;

function keyText(node: SyntaxNode | null | undefined): string | undefined {
  if (!node) return undefined;
  if (node.type === "string") return node.text.slice(1, -1);
  if (node.type === "template_string") return node.text.slice(1, -1).replace(/\$\{[^}]*\}/g, "");
  if (node.type === "identifier" || node.type === "member_expression") return node.text; // TOKEN_KEY, STORAGE_KEYS.token
  return undefined;
}

function isSecretKey(key: string | undefined): boolean {
  return !!key && SECRET_KEY.test(key) && !BENIGN_KEY.test(key);
}

export class InsecureTokenStorageAnalyzer implements Analyzer {
  analyze(parsed: ParsedFile, filePath: string, _context?: ProjectContext): Finding[] {
    const text = parsed.sourceCode;
    if (!/localStorage|sessionStorage|document\.cookie|[Cc]ookies?\.set/.test(text)) return [];
    const findings: Finding[] = [];
    const report = (node: SyntaxNode, where: string): void => {
      findings.push({
        ruleId: "insecure-token-storage",
        severity: "medium",
        confidence: "high",
        message:
          `A credential is stored in ${where}, where any script on the page can read it. One cross-site-scripting hole or one compromised ` +
          `package steals it and takes over the account. Let the server set it as a cookie with HttpOnly, Secure and SameSite flags, ` +
          `and keep it out of JavaScript.`,
        location: toLocation(node, filePath),
        sourceSnippet: "(browser storage)",
        sinkSnippet: snippet(node, parsed.sourceCode),
      });
    };

    for (const node of findNodes(parsed.tree.rootNode, (n) => n.type === "call_expression" || n.type === "assignment_expression")) {
      if (node.type === "call_expression") {
        const callee = node.childForFieldName("function");
        const args = node.childForFieldName("arguments");
        if (callee?.type !== "member_expression") continue;
        const object = callee.childForFieldName("object")?.text ?? "";
        const method = callee.childForFieldName("property")?.text;
        if (method === "setItem" && STORAGE.test(object) && isSecretKey(keyText(args?.namedChild(0)))) {
          report(node, object.replace(/^window\./, ""));
        } else if (method === "set" && /^(?:Cookies|Cookie|cookies|cookie|jsCookie)$/.test(object) && isSecretKey(keyText(args?.namedChild(0))) && !/httpOnly/i.test(args?.text ?? "")) {
          report(node, "a cookie written from JavaScript (it cannot be HttpOnly)");
        }
        continue;
      }
      const left = node.childForFieldName("left");
      if (left?.type !== "member_expression" && left?.type !== "subscript_expression") continue;
      const object = left.childForFieldName("object")?.text ?? "";
      if (STORAGE.test(object)) {
        const key = left.type === "member_expression" ? left.childForFieldName("property")?.text : keyText(left.childForFieldName("index"));
        if (isSecretKey(key)) report(node, object.replace(/^window\./, ""));
      } else if (left.text === "document.cookie") {
        const right = node.childForFieldName("right");
        const written = right ? (right.type === "string" || right.type === "template_string" ? right.text : right.text.split("+")[0] ?? "") : "";
        const name = /["'`]?\s*([\w.-]+)\s*=/.exec(written.replace(/^["'`]/, ""))?.[1];
        if (isSecretKey(name) || (/session|auth/i.test(name ?? "") && !BENIGN_KEY.test(name ?? ""))) report(node, "a cookie written from JavaScript (it cannot be HttpOnly)");
      }
    }
    return findings;
  }
}
