import { SyntaxNode } from "../parsers/utils";
import { AnalyzerConfig, BaseAnalyzer } from "./base-analyzer";
import { isRequestSource } from "./sources";

// node-serialize's unserialize() revives serialized *functions* and calls them
// (IIFE payloads) — remote code execution from a single crafted string.
const SINK_CALLEE_PATTERN = /(^|\.)(unserialize|deepDeserialize)$/;

function isSink(node: SyntaxNode): boolean {
  if (node.type !== "call_expression") return false;
  const callee = node.childForFieldName("function");
  return !!callee && (callee.type === "identifier" || callee.type === "member_expression") && SINK_CALLEE_PATTERN.test(callee.text);
}

/**
 * User-controlled data passed to a deserializer that can execute code
 * (node-serialize `unserialize`, funcster `deepDeserialize`). JSON.parse is
 * deliberately not flagged: it only builds data, never runs it.
 */
export class InsecureDeserializationAnalyzer extends BaseAnalyzer {
  protected config(): AnalyzerConfig {
    return {
      ruleId: "insecure-deserialization",
      severity: "critical",
      confidence: "medium",
      isSource: isRequestSource,
      isSink,
      messageFor: (via) =>
        `User-controlled input ('${via}') is passed to a deserializer that can execute code. ` +
        `A crafted payload runs arbitrary code on your server. Use JSON.parse (data only) and ` +
        `validate the shape, or sign the payload so only your server can have produced it.`,
    };
  }
}
