import * as fs from "fs";
import * as path from "path";
import { parseFile } from "./parsers/ast-parser";
import { collectGarbageToAvoidTreeSitterCorruption } from "./parsers/gc-workaround";
import { Analyzer } from "./analyzers/base-analyzer";
import { SqlInjectionAnalyzer } from "./analyzers/sql-injection";
import { XssAnalyzer } from "./analyzers/xss";
import { CommandInjectionAnalyzer } from "./analyzers/command-injection";
import { PathTraversalAnalyzer } from "./analyzers/path-traversal";
import { CsrfAnalyzer } from "./analyzers/csrf";
import { SsrfAnalyzer } from "./analyzers/ssrf";
import { IdorAnalyzer } from "./analyzers/idor";
import { BrokenAccessControlAnalyzer } from "./analyzers/broken-access-control";
import { InsecureRoleAssignmentAnalyzer } from "./analyzers/insecure-role-assignment";
import { InsecureFileUploadAnalyzer } from "./analyzers/insecure-file-upload";
import { UsernameEnumerationAnalyzer } from "./analyzers/username-enumeration";
import { ScanResult, ScanSummary } from "./types";

export * from "./types";
export { toSarif, toSarifString } from "./output/sarif";
export { parseFile, parseSource, languageForExtension } from "./parsers/ast-parser";

const DEFAULT_IGNORED_DIRS = new Set(["node_modules", ".git", "dist", "build", "coverage", ".next"]);
const SUPPORTED_EXTENSIONS = new Set([".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"]);

export function defaultAnalyzers(): Analyzer[] {
  return [
    new SqlInjectionAnalyzer(),
    new XssAnalyzer(),
    new CommandInjectionAnalyzer(),
    new PathTraversalAnalyzer(),
    new CsrfAnalyzer(),
    new SsrfAnalyzer(),
    new IdorAnalyzer(),
    new BrokenAccessControlAnalyzer(),
    new InsecureRoleAssignmentAnalyzer(),
    new InsecureFileUploadAnalyzer(),
    new UsernameEnumerationAnalyzer(),
  ];
}

/** Scans a single in-memory source string (no filesystem access) — handy for tests/library use. */
export function scanSource(sourceCode: string, filePath: string, analyzers: Analyzer[] = defaultAnalyzers()): ScanResult {
  let parsed;
  try {
    parsed = parseFile(filePath, sourceCode);
  } catch (err) {
    // A single malformed/unusual file must never take down a whole-project scan.
    const message = err instanceof Error ? err.message : String(err);
    return { file: filePath, findings: [], parseError: `Failed to parse: ${message}` };
  }
  if (!parsed) {
    return { file: filePath, findings: [], parseError: `Unsupported file extension: ${filePath}` };
  }
  if (parsed.tree.rootNode.hasError) {
    // Still run analyzers on the best-effort tree, but surface that parsing wasn't clean.
    const findings = analyzers.flatMap((a) => a.analyze(parsed, filePath));
    return { file: filePath, findings, parseError: "Source has syntax errors; results may be incomplete." };
  }
  const findings = analyzers.flatMap((a) => a.analyze(parsed, filePath));
  return { file: filePath, findings };
}

function walkDirectory(rootDir: string): string[] {
  const files: string[] = [];
  const stack = [rootDir];
  while (stack.length > 0) {
    const current = stack.pop() as string;
    for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
      if (entry.name.startsWith(".") && entry.name !== ".") continue;
      const fullPath = path.join(current, entry.name);
      if (entry.isDirectory()) {
        if (!DEFAULT_IGNORED_DIRS.has(entry.name)) stack.push(fullPath);
      } else if (entry.isFile() && SUPPORTED_EXTENSIONS.has(path.extname(entry.name))) {
        files.push(fullPath);
      }
    }
  }
  return files;
}

export interface ScanOptions {
  analyzers?: Analyzer[];
}

/** Recursively scans every supported JS/TS file under `targetPath` (a file or a directory). */
export function scanPath(targetPath: string, options: ScanOptions = {}): ScanSummary {
  const analyzers = options.analyzers ?? defaultAnalyzers();
  const start = Date.now();
  const stat = fs.statSync(targetPath);
  const files = stat.isDirectory() ? walkDirectory(targetPath) : [targetPath];

  // See parsers/gc-workaround.ts: scanning multiple files back-to-back in one
  // process can otherwise silently corrupt a later file's parse (a real
  // node-tree-sitter bug, not our own logic) unless we force a full GC
  // between files.
  const results: ScanResult[] = files.map((file) => {
    let sourceCode: string;
    try {
      sourceCode = fs.readFileSync(file, "utf8");
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      return { file, findings: [], parseError: `Failed to read file: ${message}` };
    }
    const result = scanSource(sourceCode, file, analyzers);
    collectGarbageToAvoidTreeSitterCorruption();
    return result;
  });

  return {
    filesScanned: files.length,
    findingsCount: results.reduce((sum, r) => sum + r.findings.length, 0),
    results,
    durationMs: Date.now() - start,
  };
}
