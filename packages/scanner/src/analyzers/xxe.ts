import { SyntaxNode } from "../parsers/utils";
import { AnalyzerConfig, BaseAnalyzer } from "./base-analyzer";
import { isRequestSource } from "./sources";

const PARSE_CALLEE_PATTERN = /(^|\.)(parseXml|parseXmlString|parseXMLString)$/;
// libxmljs resolves external entities only when noent is switched on.
const NOENT_ENABLED = /noent\s*:\s*true/;

function isSink(node: SyntaxNode): boolean {
  if (node.type !== "call_expression") return false;
  const callee = node.childForFieldName("function");
  if (!callee || !PARSE_CALLEE_PATTERN.test(callee.text)) return false;
  return NOENT_ENABLED.test(node.childForFieldName("arguments")?.text ?? "");
}

/**
 * User-controlled XML parsed with external entity expansion enabled
 * (libxmljs `{ noent: true }`). The XML can pull in local files
 * (`<!ENTITY x SYSTEM "file:///etc/passwd">`) or make the server fetch URLs.
 * Parsers that leave entities off (the default) aren't flagged.
 */
export class XxeAnalyzer extends BaseAnalyzer {
  protected config(): AnalyzerConfig {
    return {
      ruleId: "xxe",
      severity: "high",
      confidence: "medium",
      isSource: isRequestSource,
      isSink,
      messageFor: (via) =>
        `User-controlled XML ('${via}') is parsed with external entity expansion enabled (noent: true). ` +
        `An attacker can read local files or make your server fetch internal URLs. Remove noent: true ` +
        `(entities stay off by default) and don't parse untrusted XML with DTD processing.`,
    };
  }
}
