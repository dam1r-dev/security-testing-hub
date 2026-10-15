import { SyntaxNode } from "../parsers/utils";
import { AnalyzerConfig, BaseAnalyzer, firstArgument } from "./base-analyzer";
import { isRequestSource } from "./sources";

// fetch(url), request(url), got(url) — direct function calls.
const DIRECT_CALLEE_PATTERN = /^(fetch|request|got|needle|superagent|ky|phin|bent)$/;
// axios.get(url), http.get(url), https.request(url), axios({ url }) style client methods.
const HTTP_CLIENT_OBJECT_PATTERN = /^(axios|http|https|needle|superagent|got|ky|undici|phin|urllib|bent)$/;
const HTTP_CLIENT_METHOD_PATTERN = /^(get|post|put|delete|patch|head|request)$/;

// `https://oeis.org/${id}`: the scheme and the whole host are written in the code, so the caller can change the path or the
// query but not WHERE the request goes. (An attacker-chosen path on a fixed host is not server-side request forgery.)
const FIXED_HOST_PREFIX = /^[`'"]https?:\/\/[A-Za-z0-9.-]+(?::\d+)?[/?#]/;

function hasFixedHost(node: SyntaxNode): boolean {
  const first = node.childForFieldName("arguments")?.namedChild(0);
  if (!first) return false;
  if (first.type === "binary_expression") return FIXED_HOST_PREFIX.test(first.childForFieldName("left")?.text ?? "");
  return (first.type === "template_string" || first.type === "string") && FIXED_HOST_PREFIX.test(first.text);
}

function isSink(node: SyntaxNode): boolean {
  if (node.type !== "call_expression") return false;
  const callee = node.childForFieldName("function");
  if (!callee) return false;
  if (hasFixedHost(node)) return false;

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
      sinkArgs: firstArgument,
      messageFor: (via) =>
        `User-controlled input ('${via}') is used to build a URL that the server fetches. ` +
        `An attacker can point this at internal services (localhost, 169.254.169.254, private IP ranges). ` +
        `Validate against an allowlist of permitted hosts/schemes before making the request; ` +
        `block requests to loopback/link-local/private address ranges.`,
    };
  }
}
