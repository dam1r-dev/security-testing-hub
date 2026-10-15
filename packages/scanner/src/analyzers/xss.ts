import { SyntaxNode } from "../parsers/utils";
import { AnalyzerConfig, BaseAnalyzer, firstArgument } from "./base-analyzer";
import { isRequestSource } from "./sources";

const RESPONSE_OBJECT_PATTERN = /^(res|response)$/;
const RESPONSE_METHOD_PATTERN = /^(send|write|end)$/;

function isExpressSink(node: SyntaxNode): boolean {
  if (node.type !== "call_expression") return false;
  const callee = node.childForFieldName("function");
  if (!callee || callee.type !== "member_expression") return false;
  const object = callee.childForFieldName("object");
  const property = callee.childForFieldName("property");
  if (!object || !property) return false;
  if (!RESPONSE_OBJECT_PATTERN.test(object.text) || !RESPONSE_METHOD_PATTERN.test(property.text)) return false;
  // res.send({ ... }) / res.send([...]) is serialised as JSON (Content-Type: application/json),
  // which a browser never renders as HTML — echoing request data there is not reflected XSS.
  const first = node.childForFieldName("arguments")?.namedChild(0);
  return first?.type !== "object" && first?.type !== "array";
}

// Next.js / Web API: `new Response(html, ...)` / `new NextResponse(html, ...)` with a
// raw body — unlike NextResponse.json(...), this doesn't escape anything for you.
function isWebResponseSink(node: SyntaxNode): boolean {
  if (node.type !== "new_expression") return false;
  const constructor = node.childForFieldName("constructor");
  if (!constructor || !/^(Response|NextResponse)$/.test(constructor.text)) return false;
  // `new Response(text)` is sent as text/plain: a browser shows it, it does not run it. Only a body that is declared to be HTML
  // can script the page; and a Response used to read a stream (`new Response(request.body).arrayBuffer()`) is not sent at all.
  const options = node.childForFieldName("arguments")?.namedChild(1);
  return !!options && /html/i.test(options.text);
}

// Hono: c.html(markup) sends text/html.
function isHonoHtmlSink(node: SyntaxNode): boolean {
  if (node.type !== "call_expression") return false;
  const callee = node.childForFieldName("function");
  return callee?.type === "member_expression" && /^(?:c|ctx|context).html$/.test(callee.text);
}

function isSink(node: SyntaxNode): boolean {
  return isExpressSink(node) || isWebResponseSink(node) || isHonoHtmlSink(node);
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
      isSource: isRequestSource,
      isSink,
      sinkArgs: firstArgument,
      messageFor: (via) =>
        `User-controlled input ('${via}') is written directly into the HTTP response without escaping. ` +
        `Escape output (e.g. a templating engine's auto-escaping, or a library like 'escape-html') before sending it.`,
    };
  }
}
