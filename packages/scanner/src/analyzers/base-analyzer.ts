import { ParsedFile } from "../parsers/ast-parser";
import { SyntaxNode, findFunctionBodies, findNodes, snippet, toLocation } from "../parsers/utils";
import { CrossFileFlow, findCrossFileFlows, firstArgument } from "../taint/interprocedural";
import { ProjectContext } from "../taint/project";
import { requestParamOrigins } from "../taint/request-params";
import { analyzeFunctionBody } from "../taint/simple-taint";
import { Finding, Severity, VulnerabilityType } from "../types";

export interface Analyzer {
  /**
   * `context` lets taint-based analyzers follow calls into other files of the same
   * scan; without it they only see helpers defined in `parsed` itself.
   */
  analyze(parsed: ParsedFile, filePath: string, context?: ProjectContext): Finding[];
}

export { firstArgument };

export interface AnalyzerConfig {
  ruleId: VulnerabilityType;
  severity: Severity;
  confidence: "high" | "medium" | "low";
  isSource: (node: SyntaxNode) => boolean;
  isSink: (node: SyntaxNode) => boolean;
  /**
   * Which arguments of a sink call must not be attacker-controlled. Used when following
   * a value through a helper function, where "any argument" is too coarse: for
   * `query(sql, params)` only `sql` is dangerous, `params` is the safe bound-values slot.
   * Default: all arguments.
   */
  sinkArgs?: (sink: SyntaxNode) => SyntaxNode[];
  /**
   * Which parts of a destructured request parameter count as input for this rule
   * (`({ body, query }: Request, res) => ...`). Default: body, query, params, cookies, headers, file(s).
   */
  paramKeys?: readonly string[];
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

  analyze(parsed: ParsedFile, filePath: string, context?: ProjectContext): Finding[] {
    const cfg = this.config();
    const findings: Finding[] = [];
    const root = parsed.tree.rootNode;
    const functionBodies = findFunctionBodies(root);

    // Also analyze top-level (module scope) code, not just inside functions.
    const scopes = functionBodies.length > 0 ? functionBodies : [root];

    const project = context ?? ProjectContext.forSingleFile(filePath, parsed);
    const info = project.fileInfo(filePath, parsed);
    const spec = { ruleId: cfg.ruleId, isSink: cfg.isSink, sinkArgs: cfg.sinkArgs };

    // Nested functions are their own scope AND part of their parent's subtree,
    // so the same sink can be visited twice; dedupe by sink location.
    const seenSinks = new Set<string>();
    const nodeKey = (node: SyntaxNode): string => `${node.startIndex}:${node.endIndex}`;

    for (const scope of scopes) {
      const sources = info ? info.sourcesIn(scope, cfg.isSource) : findNodes(scope, cfg.isSource);
      const origins = requestParamOrigins(scope, cfg.paramKeys);
      if (sources.length === 0 && origins.length === 0) continue; // nothing user-controlled in this function
      const pairs = analyzeFunctionBody(scope, cfg.isSource, cfg.isSink, {
        sources,
        assignments: info?.assignmentsIn(scope),
        sinkArgs: cfg.sinkArgs,
        origins,
      });
      for (const pair of pairs) {
        const sinkKey = nodeKey(pair.sink);
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

      // User input handed to a function (in this file or another) that passes it to a sink.
      const flows: CrossFileFlow[] = info ? findCrossFileFlows(scope, spec, sources, info, origins) : [];
      for (const flow of flows) {
        const callKey = nodeKey(flow.call);
        if (seenSinks.has(callKey)) continue;
        seenSinks.add(callKey);
        const where = `${project.displayPath(flow.trace.file)}:${flow.trace.line}`;
        const chain = flow.trace.path.length > 1 ? ` (via ${flow.trace.path.join(" -> ")})` : "";
        findings.push({
          ruleId: cfg.ruleId,
          severity: cfg.severity,
          confidence: cfg.confidence,
          message:
            `${cfg.messageFor(flow.via)} The value is passed to ${flow.calleeName}() and reaches ` +
            `the vulnerable call at ${where}${chain}.`,
          location: toLocation(flow.call, filePath),
          sourceSnippet: snippet(flow.source, parsed.sourceCode),
          sinkSnippet: snippet(flow.call, parsed.sourceCode),
        });
      }
    }

    return findings;
  }
}
