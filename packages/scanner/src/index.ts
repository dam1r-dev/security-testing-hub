import * as fs from "fs";
import * as path from "path";
import { parseFile } from "./parsers/ast-parser";
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
import { CodeInjectionAnalyzer } from "./analyzers/code-injection";
import { OpenRedirectAnalyzer } from "./analyzers/open-redirect";
import { NoSqlInjectionAnalyzer } from "./analyzers/nosql-injection";
import { InsecureDeserializationAnalyzer } from "./analyzers/insecure-deserialization";
import { XxeAnalyzer } from "./analyzers/xxe";
import { HardcodedSecretAnalyzer } from "./analyzers/hardcoded-secret";
import { scanEnvFiles } from "./secrets/env-files";
import { applyInlineSuppressions, compileIgnorePatterns, parseIgnoreFile } from "./suppress";
import { ProjectContext } from "./taint/project";
import { ScanResult, ScanSummary } from "./types";

export * from "./types";
export { toSarif, toSarifString, SarifOptions } from "./output/sarif";
export { computeScore, SecurityScore, ScoreColor } from "./output/score";
export { toHtml } from "./output/html";
export { toMarkdown, MARKDOWN_MARKER, MarkdownOptions } from "./output/markdown";
export { toGithubAnnotations, annotationFor } from "./output/github";
export { filterSummary, FilterOptions, SEVERITY_RANK } from "./filter";
export { changedFiles } from "./changed";
export { parseFile, parseSource, languageForExtension } from "./parsers/ast-parser";
export { ProjectContext } from "./taint/project";
export { RULE_IDS } from "./suppress";

// Directories that aren't the project's own hand-written server code:
//  - build output / dependencies / VCS metadata
//  - `generated` / `__generated__`: machine-written code (Prisma client, GraphQL
//    codegen, ...) that often uses syntax our parser doesn't know yet
//  - `vendor` / `vendors`: bundled third-party libraries (jquery.min.js, ...)
//  - test directories: tests deliberately contain "wrong password" strings,
//    fake requests and mocks — measured on real projects, this was the single
//    biggest source of false positives (username-enumeration on test files).
const DEFAULT_IGNORED_DIRS = new Set([
  "node_modules",
  ".git",
  "dist",
  "build",
  "coverage",
  ".next",
  "generated",
  "__generated__",
  "vendor",
  "vendors",
]);
// Skipped unless `includeTests` is set (see ScanOptions).
const TEST_DIRS = new Set(["test", "tests", "__tests__", "__mocks__", "e2e", "cypress"]);
// *.test.js / *.spec.ts (tests living next to the code) and minified bundles.
const MINIFIED_FILE_PATTERN = /\.min\.[cm]?js$/i;
const TEST_FILE_PATTERN = /\.(test|spec)\.[cm]?[jt]sx?$/i;
/** Optional project-level ignore list, one path pattern per line (see docs/rules.md). */
export const IGNORE_FILE_NAME = ".security-hub-ignore";
// Hand-written source is far below this. A multi-megabyte file is a bundle or generated
// output: it can take minutes to analyse (a 9 MB typescript.js took 52 s) and holds no
// code a person wrote. Skipped with a visible warning rather than silently.
const MAX_FILE_BYTES = 2 * 1024 * 1024;
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
    new CodeInjectionAnalyzer(),
    new OpenRedirectAnalyzer(),
    new NoSqlInjectionAnalyzer(),
    new InsecureDeserializationAnalyzer(),
    new XxeAnalyzer(),
    new HardcodedSecretAnalyzer(),
  ];
}

/** Scans a single in-memory source string (no filesystem access) — handy for tests/library use. */
export function scanSource(
  sourceCode: string,
  filePath: string,
  analyzers: Analyzer[] = defaultAnalyzers(),
  context?: ProjectContext,
): ScanResult {
  let parsed;
  try {
    parsed = context?.cachedParse(filePath, sourceCode) ?? parseFile(filePath, sourceCode);
  } catch (err) {
    // A single malformed/unusual file must never take down a whole-project scan.
    const message = err instanceof Error ? err.message : String(err);
    return { file: filePath, findings: [], parseError: `Failed to parse: ${message}` };
  }
  if (!parsed) {
    return { file: filePath, findings: [], parseError: `Unsupported file extension: ${filePath}` };
  }
  const { kept, suppressed } = applyInlineSuppressions(
    analyzers.flatMap((a) => a.analyze(parsed, filePath, context)),
    sourceCode,
  );
  const result: ScanResult = { file: filePath, findings: kept };
  if (suppressed > 0) result.suppressed = suppressed;
  if (parsed.tree.rootNode.hasError) {
    // The analyzers still ran on the best-effort tree, but surface that parsing wasn't clean.
    result.parseError = "Source has syntax errors; results may be incomplete.";
  }
  return result;
}

interface WalkOptions {
  includeTests: boolean;
  isIgnored: (relativePath: string) => boolean;
}

function walkDirectory(rootDir: string, options: WalkOptions): string[] {
  const files: string[] = [];
  const stack = [rootDir];
  while (stack.length > 0) {
    const current = stack.pop() as string;
    for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
      if (entry.name.startsWith(".") && entry.name !== ".") continue;
      const fullPath = path.join(current, entry.name);
      if (options.isIgnored(path.relative(rootDir, fullPath).split(path.sep).join("/"))) continue;
      if (entry.isDirectory()) {
        if (DEFAULT_IGNORED_DIRS.has(entry.name)) continue;
        if (!options.includeTests && TEST_DIRS.has(entry.name)) continue;
        stack.push(fullPath);
      } else if (
        entry.isFile() &&
        SUPPORTED_EXTENSIONS.has(path.extname(entry.name)) &&
        !MINIFIED_FILE_PATTERN.test(entry.name) &&
        (options.includeTests || !TEST_FILE_PATTERN.test(entry.name))
      ) {
        files.push(fullPath);
      }
    }
  }
  return files;
}

export interface ScanOptions {
  analyzers?: Analyzer[];
  /** Also scan test folders (`test`, `__tests__`, `e2e`, ...) and `*.test.*` / `*.spec.*` files. Default: false. */
  includeTests?: boolean;
  /**
   * Extra path patterns to skip, relative to the scanned folder (gitignore-style subset:
   * `*`, `**`, `?`, leading `/`, trailing `/`). Added to the patterns in `.security-hub-ignore`.
   */
  ignore?: string[];
}

function readIgnoreFile(rootDir: string): string[] {
  try {
    return parseIgnoreFile(fs.readFileSync(path.join(rootDir, IGNORE_FILE_NAME), "utf8"));
  } catch {
    return []; // no ignore file: nothing extra to skip
  }
}

/** Recursively scans every supported JS/TS file under `targetPath` (a file or a directory). */
export function scanPath(targetPath: string, options: ScanOptions = {}): ScanSummary {
  const analyzers = options.analyzers ?? defaultAnalyzers();
  const start = Date.now();
  const stat = fs.statSync(targetPath);
  const includeTests = options.includeTests ?? false;
  const isIgnored = compileIgnorePatterns([...readIgnoreFile(targetPath), ...(options.ignore ?? [])]);
  const files = stat.isDirectory() ? walkDirectory(targetPath, { includeTests, isIgnored }) : [targetPath];
  // Shared by every file of this scan so a call can be followed into another file.
  const context = new ProjectContext(stat.isDirectory() ? targetPath : path.dirname(targetPath));

  const results: ScanResult[] = files.map((file) => {
    let sourceCode: string;
    try {
      const size = fs.statSync(file).size;
      if (size > MAX_FILE_BYTES) {
        return {
          file,
          findings: [],
          parseError: `Skipped: ${(size / 1024 / 1024).toFixed(1)} MB is over the ${MAX_FILE_BYTES / 1024 / 1024} MB limit (likely a bundle or generated file).`,
        };
      }
      sourceCode = fs.readFileSync(file, "utf8");
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      return { file, findings: [], parseError: `Failed to read file: ${message}` };
    }
    return scanSource(sourceCode, file, analyzers, context);
  });

  // `.env` files are not source code, but a committed one is the most common secret leak.
  const envResults = stat.isDirectory()
    ? scanEnvFiles(targetPath, new Set([...DEFAULT_IGNORED_DIRS, ...(includeTests ? [] : TEST_DIRS)]), isIgnored)
    : [];
  results.push(...envResults);

  return {
    filesScanned: files.length + envResults.length,
    findingsCount: results.reduce((sum, r) => sum + r.findings.length, 0),
    results,
    durationMs: Date.now() - start,
    suppressedCount: results.reduce((sum, r) => sum + (r.suppressed ?? 0), 0),
  };
}
