import { SyntaxNode } from "../parsers/utils";
import { AnalyzerConfig, BaseAnalyzer } from "./base-analyzer";
import { isRequestSource } from "./sources";

const FS_METHOD_PATTERN =
  /^(readFile|readFileSync|writeFile|writeFileSync|appendFile|appendFileSync|unlink|unlinkSync|createReadStream|createWriteStream|open|openSync)$/;
const FS_OBJECT_PATTERN = /^(fs|fsPromises|promises)$/;

function isSink(node: SyntaxNode): boolean {
  if (node.type !== "call_expression") return false;
  const callee = node.childForFieldName("function");
  if (!callee || callee.type !== "member_expression") return false;
  const object = callee.childForFieldName("object");
  const property = callee.childForFieldName("property");
  if (!object || !property) return false;
  return FS_OBJECT_PATTERN.test(object.text) && FS_METHOD_PATTERN.test(property.text);
}

/**
 * Detects user-controlled input used to build a filesystem path passed to
 * fs.* file-access calls, without a visible sanitization/resolve+containment
 * check in between (intra-procedural: same simplification as SQL injection).
 */
export class PathTraversalAnalyzer extends BaseAnalyzer {
  protected config(): AnalyzerConfig {
    return {
      ruleId: "path-traversal",
      severity: "high",
      confidence: "low",
      isSource: isRequestSource,
      isSink,
      messageFor: (via) =>
        `User-controlled input ('${via}') is used to build a filesystem path. ` +
        `An attacker could supply '../' segments to escape the intended directory. ` +
        `Resolve the path and verify it stays within an allowed base directory before using it.`,
    };
  }
}
