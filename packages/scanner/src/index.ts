import * as fs from "fs";
import * as path from "path";
import { BudgetExceeded, FILE_BUDGET_MS, startBudget } from "./budget";
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
import { SupabaseAuthAnalyzer } from "./analyzers/supabase-auth";
import { ServerActionAnalyzer } from "./analyzers/server-actions";
import { InsecureCorsAnalyzer } from "./analyzers/cors";
import { InsecureJwtAnalyzer } from "./analyzers/jwt";
import { MissingRateLimitAnalyzer } from "./analyzers/rate-limit";
import { scanExposedFiles } from "./backend/exposed";
import { scanBackendConfigs } from "./backend/discover";
import { scanEnvFiles } from "./secrets/env-files";
import { emptyConfig, HubConfig, loadConfig } from "./config";
import { applyInlineSuppressions, compileIgnorePatterns, parseIgnoreFile } from "./suppress";
import { ProjectContext } from "./taint/project";
import { Finding, ScanResult, ScanSummary } from "./types";

export * from "./types";
export { toSarif, toSarifString, SarifOptions } from "./output/sarif";
export { computeScore, SecurityScore, ScoreColor } from "./output/score";
export { toHtml } from "./output/html";
export { MASCOT_NAME, MASCOT_IMAGE_BASE, mascotDataUri, mascotImageUrl, mascotSay, mascotAlt } from "./output/mascot";
export { toMarkdown, MARKDOWN_MARKER, MarkdownOptions } from "./output/markdown";
export { toGithubAnnotations, annotationFor } from "./output/github";
export { fixPromptFor, toFixPrompt, fenced, FixPromptOptions } from "./output/fix-prompt";
export { filterSummary, FilterOptions, SEVERITY_RANK } from "./filter";
export { changedFiles } from "./changed";
export { GIT_HARDENING_ARGS, gitEnvironment } from "./git-safe";
export { parseFile, parseSource, languageForExtension } from "./parsers/ast-parser";
export { ProjectContext } from "./taint/project";
export { RULE_IDS } from "./suppress";
export { CONFIG_FILE_NAME, ConfigError, HubConfig, emptyConfig, loadConfig, parseConfig } from "./config";
export { BASELINE_FILE_NAME, Baseline, BaselineError, applyBaseline, createBaseline, loadBaseline, parseBaseline, serializeBaseline } from "./baseline";
export { planFixes, renderPlan, applyPlan, FIXABLE_RULES, FixPlan, FixOptions, ApplyOptions } from "./fix/plan";

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
// Also `test-suite.ts`, `test_users.js`, `login-test.ts`: a test script kept next to the code (seen in a real project:
// its fake sign-up passwords were reported as leaked credentials).
const TEST_FILE_PATTERN = /(?:\.(?:test|spec)|[-_](?:test|tests|spec)|^(?:test|tests|spec)[-_][^.]*)\.[cm]?[jt]sx?$/i;
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
    new SupabaseAuthAnalyzer(),
    new ServerActionAnalyzer(),
    new InsecureCorsAnalyzer(),
    new InsecureJwtAnalyzer(),
    new MissingRateLimitAnalyzer(),
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
  // One analyzer failing (or one hostile file wearing out the time budget) must not take down the scan: the file is
  // reported with a note, the other checks keep their findings, and the next file is scanned normally.
  const found: Finding[] = [];
  const notes: string[] = [];
  const endBudget = startBudget();
  try {
    for (const analyzer of analyzers) {
      try {
        found.push(...analyzer.analyze(parsed, filePath, context));
      } catch (err) {
        if (err instanceof BudgetExceeded) {
          notes.push(`Analysis stopped after ${FILE_BUDGET_MS / 1000} s: the file is too large or too complex to finish, so results for it may be incomplete.`);
          break;
        }
        const message = err instanceof Error ? err.message : String(err);
        notes.push(`One check (${analyzer.constructor.name}) could not finish: ${message.split("\n")[0]}.`);
      }
    }
  } finally {
    endBudget();
  }
  const { kept, suppressed } = applyInlineSuppressions(found, sourceCode);
  const result: ScanResult = { file: filePath, findings: kept };
  if (suppressed > 0) result.suppressed = suppressed;
  if (parsed.tree.rootNode.hasError) {
    // The analyzers still ran on the best-effort tree, but surface that parsing wasn't clean.
    notes.unshift("Source has syntax errors; results may be incomplete.");
  }
  if (notes.length > 0) result.parseError = notes.join(" ");
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
  /**
   * The project's settings (`.security-hub.json`). Default: read from the scanned folder. Pass your own to use those instead,
   * or `false` to ignore any file there. Flags given in `ignore` / `includeTests` win over the file.
   */
  config?: HubConfig | false;
  /** Called after every scanned file: how many are done of how many (the web page shows a progress bar). */
  onProgress?: (done: number, total: number) => void;
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
  const config = options.config === false ? emptyConfig() : (options.config ?? loadConfig(stat.isDirectory() ? targetPath : path.dirname(targetPath)).config);
  const includeTests = options.includeTests ?? config.includeTests ?? false;
  const isIgnored = compileIgnorePatterns([...config.ignore, ...readIgnoreFile(targetPath), ...(options.ignore ?? [])]);
  const files = stat.isDirectory() ? walkDirectory(targetPath, { includeTests, isIgnored }) : [targetPath];
  // Shared by every file of this scan so a call can be followed into another file.
  const context = new ProjectContext(stat.isDirectory() ? targetPath : path.dirname(targetPath));

  const results: ScanResult[] = files.map((file, index) => {
    options.onProgress?.(index, files.length);
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

  // Files that are not source code but decide who can read the data: Supabase migrations, Firebase rules.
  const skipDirs = new Set([...DEFAULT_IGNORED_DIRS, ...(includeTests ? [] : TEST_DIRS)]);
  const backendResults = stat.isDirectory() ? scanBackendConfigs(targetPath, skipDirs, isIgnored) : [];
  results.push(...backendResults);

  // Secrets, keys, dumps and .git folders inside the folders the web server hands out (public/, static/, express.static).
  const exposedResults = stat.isDirectory() ? scanExposedFiles(targetPath, skipDirs, isIgnored) : [];
  results.push(...exposedResults);

  // Rules the project switched off: dropped here, but counted so the report can say so.
  let disabledCount = 0;
  if (config.disable.length > 0) {
    const off = new Set<string>(config.disable);
    for (const result of results) {
      const kept = result.findings.filter((f) => !off.has(f.ruleId));
      disabledCount += result.findings.length - kept.length;
      result.findings = kept;
    }
  }

  return {
    filesScanned: files.length + envResults.length + backendResults.length + exposedResults.length,
    findingsCount: results.reduce((sum, r) => sum + r.findings.length, 0),
    results,
    durationMs: Date.now() - start,
    suppressedCount: results.reduce((sum, r) => sum + (r.suppressed ?? 0), 0),
    ...(disabledCount > 0 ? { disabledCount } : {}),
  };
}
