import { SyntaxNode } from "../parsers/utils";
import { AnalyzerConfig, BaseAnalyzer } from "./base-analyzer";

const SOURCE_PATTERN = /^req\.(params|query|body|cookies|headers)(\.\w+|\[[^\]]*\])?$/;

// child_process.exec / execSync spawn a shell and interpret the whole string,
// which is what makes them command-injection sinks (unlike execFile/spawn with an argv array).
const SINK_CALLEE_PATTERN = /(^|\.)(exec|execSync)$/;

function isSource(node: SyntaxNode): boolean {
  if (node.type !== "member_expression" && node.type !== "subscript_expression") return false;
  return SOURCE_PATTERN.test(node.text);
}

function isSink(node: SyntaxNode): boolean {
  if (node.type !== "call_expression") return false;
  const callee = node.childForFieldName("function");
  if (!callee) return false;
  if (callee.type !== "member_expression" && callee.type !== "identifier") return false;
  return SINK_CALLEE_PATTERN.test(callee.text);
}

/**
 * Detects user-controlled input reaching child_process.exec/execSync, which
 * runs its string argument through a shell (`/bin/sh -c` / `cmd.exe /c`).
 *
 * execFile/spawn are intentionally NOT flagged: passed an argv array, the
 * shell never re-interprets the string, so they aren't vulnerable to this class.
 */
export class CommandInjectionAnalyzer extends BaseAnalyzer {
  protected config(): AnalyzerConfig {
    return {
      ruleId: "command-injection",
      severity: "critical",
      confidence: "medium",
      isSource,
      isSink,
      messageFor: (via) =>
        `User-controlled input ('${via}') flows into a shell command. ` +
        `Use child_process.execFile/spawn with an argument array instead of exec/execSync with a built string.`,
    };
  }
}
