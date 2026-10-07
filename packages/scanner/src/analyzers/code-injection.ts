import { SyntaxNode } from "../parsers/utils";
import { AnalyzerConfig, BaseAnalyzer } from "./base-analyzer";
import { isRequestSource } from "./sources";

// eval(x), Function(x), vm.runInNewContext(x), mathjs/math.eval(x) — all
// compile and run a string as code.
const CALLEE_PATTERN = /^(eval|Function)$|(^|\.)(eval|runInNewContext|runInThisContext|runInContext)$/;
// new Function(x), new vm.Script(x)
const CONSTRUCTOR_PATTERN = /^Function$|(^|\.)Script$/;

function isSink(node: SyntaxNode): boolean {
  if (node.type === "call_expression") {
    const callee = node.childForFieldName("function");
    return !!callee && (callee.type === "identifier" || callee.type === "member_expression") && CALLEE_PATTERN.test(callee.text);
  }
  if (node.type === "new_expression") {
    const ctor = node.childForFieldName("constructor");
    return !!ctor && CONSTRUCTOR_PATTERN.test(ctor.text);
  }
  return false;
}

/**
 * User-controlled input reaching eval()/new Function()/vm.run*()/math.eval().
 * The attacker's string runs with the server's privileges — full remote code
 * execution, not just a data leak.
 */
export class CodeInjectionAnalyzer extends BaseAnalyzer {
  protected config(): AnalyzerConfig {
    return {
      ruleId: "code-injection",
      severity: "critical",
      confidence: "medium",
      isSource: isRequestSource,
      isSink,
      messageFor: (via) =>
        `User-controlled input ('${via}') is executed as code (eval / Function / vm / math.eval). ` +
        `An attacker can run arbitrary JavaScript on your server. Parse the input as data instead ` +
        `(JSON.parse, Number(), a schema validator) and never evaluate it.`,
    };
  }
}
