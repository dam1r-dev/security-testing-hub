import { SyntaxNode } from "../parsers/utils";
import { AnalyzerConfig, BaseAnalyzer } from "./base-analyzer";

const SOURCE_PATTERN = /^req\.(params|query|body|cookies|headers)(\.\w+|\[[^\]]*\])?$/;
const RESPONSE_OBJECT_PATTERN = /^(res|response)$/;
const RESPONSE_METHOD_PATTERN = /^(send|write|end)$/;

function isSource(node: SyntaxNode): boolean {
  if (node.type !== "member_expression" && node.type !== "subscript_expression") return false;
  return SOURCE_PATTERN.test(node.text);
}

function isSink(node: SyntaxNode): boolean {
  if (node.type !== "call_expression") return false;
  const callee = node.childForFieldName("function");
  if (!callee || callee.type !== "member_expression") return false;
  const object = callee.childForFieldName("object");
  const property = callee.childForFieldName("property");
  if (!object || !property) return false;
  return RESPONSE_OBJECT_PATTERN.test(object.text) && RESPONSE_METHOD_PATTERN.test(property.text);
}

/**
 * Detects reflected XSS: request data written straight into an HTTP response
 * body (res.send/write/end) without escaping.
 *
 * Note: res.render(...) with a template engine is NOT flagged — template
 * engines like EJS/Pug auto-escape by default, so that path is out of scope
 * for this heuristic (same simplification tradeoff as the plan's v1 scope).
 */
export class XssAnalyzer extends BaseAnalyzer {
  protected config(): AnalyzerConfig {
    return {
      ruleId: "xss",
      severity: "high",
      confidence: "medium",
      isSource,
      isSink,
      messageFor: (via) =>
        `User-controlled input ('${via}') is written directly into the HTTP response without escaping. ` +
        `Escape output (e.g. a templating engine's auto-escaping, or a library like 'escape-html') before sending it.`,
    };
  }
}
