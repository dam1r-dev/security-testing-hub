import { ParsedFile } from "../parsers/ast-parser";
import { SyntaxNode, findFunctionBodies, snippet, toLocation } from "../parsers/utils";
import { analyzeFunctionBody } from "../taint/simple-taint";
import { Finding, Severity, VulnerabilityType } from "../types";

export interface Analyzer {
  analyze(parsed: ParsedFile, filePath: string): Finding[];
}

export interface AnalyzerConfig {
  ruleId: VulnerabilityType;
  severity: Severity;
  confidence: "high" | "medium" | "low";
  isSource: (node: SyntaxNode) => boolean;
  isSink: (node: SyntaxNode) => boolean;
  messageFor: (taintedVia: string) => string;
}

/**
 * Shared driver for every analyzer: run intra-procedural taint tracking
 * over each function body in the file using the analyzer's source/sink
 * predicates, and turn matches into Findings.
 *
 * Analyzers scan each function independently, per the intra-procedural
 * scope defined in the dev plan (Phase 2).
 */
export abstract class BaseAnalyzer implements Analyzer {
  protected abstract config(): AnalyzerConfig;

  analyze(parsed: ParsedFile, filePath: string): Finding[] {
    const cfg = this.config();
    const findings: Finding[] = [];
    const root = parsed.tree.rootNode;
    const functionBodies = findFunctionBodies(root);

    // Also analyze top-level (module scope) code, not just inside functions.
    const scopes = functionBodies.length > 0 ? functionBodies : [root];

    // Nested functions are their own scope AND part of their parent's subtree,
    // so the same sink can be visited twice; dedupe by sink location.
    const seenSinks = new Set<string>();

    for (const scope of scopes) {
      const pairs = analyzeFunctionBody(scope, cfg.isSource, cfg.isSink);
      for (const pair of pairs) {
        const sinkKey = `${pair.sink.startIndex}:${pair.sink.endIndex}`;
        if (seenSinks.has(sinkKey)) continue;
        seenSinks.add(sinkKey);
        findings.push({
          ruleId: cfg.ruleId,
          severity: cfg.severity,
          confidence: cfg.confidence,
          message: cfg.messageFor(pair.taintedVia),
          location: toLocation(pair.sink, filePath),
          sourceSnippet: snippet(pair.source, parsed.sourceCode),
          sinkSnippet: snippet(pair.sink, parsed.sourceCode),
        });
      }
    }

    return findings;
  }
}
