import { SyntaxNode } from "../parsers/utils";
import { AnalyzerConfig, BaseAnalyzer } from "./base-analyzer";
import { isRequestSource } from "./sources";

// fetch(url), request(url), got(url) — direct function calls.
const DIRECT_CALLEE_PATTERN = /^(fetch|request|got)$/;
// axios.get(url), http.get(url), https.request(url), axios({ url }) style client methods.
const HTTP_CLIENT_OBJECT_PATTERN = /^(axios|http|https)$/;
const HTTP_CLIENT_METHOD_PATTERN = /^(get|post|put|delete|patch|head|request)$/;

function isSink(node: SyntaxNode): boolean {
  if (node.type !== "call_expression") return false;
  const callee = node.childForFieldName("function");
  if (!callee) return false;

  if (callee.type === "identifier") {
    return DIRECT_CALLEE_PATTERN.test(callee.text);
  }

  if (callee.type === "member_expression") {
    const object = callee.childForFieldName("object");
    const property = callee.childForFieldName("property");
    if (!object || !property) return false;
    return HTTP_CLIENT_OBJECT_PATTERN.test(object.text) && HTTP_CLIENT_METHOD_PATTERN.test(property.text);
  }

  return false;
}

/**
 * Detects Server-Side Request Forgery: user-controlled input used to build a
 * URL that the server itself then fetches (fetch/axios/http(s)/request/got).
 * An attacker can point this at internal services (http://localhost/admin,
 * http://169.254.169.254/ cloud metadata, internal 10.x/192.168.x hosts)
 * that aren't reachable from outside.
 */
export class SsrfAnalyzer extends BaseAnalyzer {
  protected config(): AnalyzerConfig {
    return {
      ruleId: "ssrf",
      severity: "high",
      confidence: "medium",
      isSource: isRequestSource,
      isSink,
      messageFor: (via) =>
        `User-controlled input ('${via}') is used to build a URL that the server fetches. ` +
        `An attacker can point this at internal services (localhost, 169.254.169.254, private IP ranges). ` +
        `Validate against an allowlist of permitted hosts/schemes before making the request; ` +
        `block requests to loopback/link-local/private address ranges.`,
    };
  }
}
