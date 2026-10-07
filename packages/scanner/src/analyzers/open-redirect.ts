import { SyntaxNode } from "../parsers/utils";
import { AnalyzerConfig, BaseAnalyzer } from "./base-analyzer";
import { isRequestSource } from "./sources";

// Express res.redirect / res.location, Koa ctx.redirect, Fastify reply.redirect.
const RESPONSE_OBJECT_PATTERN = /^(res|response|reply|ctx)$/;
const RESPONSE_METHOD_PATTERN = /^(redirect|location)$/;
// Web / Next.js: NextResponse.redirect(url), Response.redirect(url).
const WEB_RESPONSE_PATTERN = /^(NextResponse|Response)$/;
// next/navigation: redirect(url), permanentRedirect(url).
const BARE_CALLEE_PATTERN = /^(redirect|permanentRedirect)$/;

// A target that starts with "/x" (one slash, then a real path character) keeps
// the browser on this site: whatever gets appended can't change the host.
// "//evil.com" and "/\evil.com" are deliberately NOT treated as safe.
const SAME_SITE_PREFIX = /^["'`]\/[^/\\"'`]/;

function leftmostText(node: SyntaxNode): string {
  if (node.type === "binary_expression") {
    const left = node.childForFieldName("left");
    return left ? leftmostText(left) : node.text;
  }
  if (node.type === "template_string") {
    return node.text;
  }
  return node.text;
}

function hasFixedSameSitePrefix(target: SyntaxNode): boolean {
  if (target.type !== "binary_expression" && target.type !== "template_string") return false;
  return SAME_SITE_PREFIX.test(leftmostText(target));
}

function isRedirectCall(node: SyntaxNode): boolean {
  if (node.type !== "call_expression") return false;
  const callee = node.childForFieldName("function");
  if (!callee) return false;
  if (callee.type === "identifier") return BARE_CALLEE_PATTERN.test(callee.text);
  if (callee.type !== "member_expression") return false;
  const object = callee.childForFieldName("object");
  const property = callee.childForFieldName("property");
  if (!object || !property) return false;
  if (RESPONSE_OBJECT_PATTERN.test(object.text) && RESPONSE_METHOD_PATTERN.test(property.text)) return true;
  return WEB_RESPONSE_PATTERN.test(object.text) && property.text === "redirect";
}

function redirectTarget(node: SyntaxNode): SyntaxNode | null | undefined {
  const args = node.childForFieldName("arguments");
  // res.redirect(302, url) takes the target second; otherwise it's the first.
  const first = args?.namedChild(0);
  return first?.type === "number" ? args?.namedChild(1) : first;
}

function isSink(node: SyntaxNode): boolean {
  if (!isRedirectCall(node)) return false;
  const target = redirectTarget(node);
  if (!target) return false;
  return !hasFixedSameSitePrefix(target);
}

/**
 * User-controlled input deciding where the server redirects the browser
 * (`res.redirect(req.query.url)`). Attackers send victims a link on YOUR
 * domain that bounces them to a phishing page, borrowing your reputation.
 * Redirects to a fixed same-site path with something appended
 * (`"/items/" + id`) are not flagged — the host can't change.
 */
export class OpenRedirectAnalyzer extends BaseAnalyzer {
  protected config(): AnalyzerConfig {
    return {
      ruleId: "open-redirect",
      severity: "medium",
      confidence: "medium",
      isSource: isRequestSource,
      isSink,
      sinkArgs: (sink) => {
        const target = redirectTarget(sink);
        return target ? [target] : [];
      },
      messageFor: (via) =>
        `User-controlled input ('${via}') decides where the server redirects. An attacker can send a link ` +
        `on your domain that bounces victims to a phishing site. Only redirect to relative paths you build ` +
        `yourself, or check the target against an allowlist of hosts first.`,
    };
  }
}
