import * as fs from "fs";
import * as path from "path";
import chalk from "chalk";
import {
  scanPath,
  toSarifString,
  toHtml,
  toMarkdown,
  toGithubAnnotations,
  toFixPrompt,
  changedFiles,
  filterSummary,
  SEVERITY_RANK,
  computeScore,
  Finding,
  ScanSummary,
  Severity,
  ScoreColor,
} from "security-hub-scanner";

export interface ScanCommandOptions {
  format: "text" | "json" | "sarif" | "html" | "markdown" | "github" | "prompt";
  out?: string;
  severity?: Severity;
  failOn?: Severity;
  /** Extra path patterns to skip (on top of `.security-hub-ignore`). */
  ignore?: string[];
  /** Also scan test folders and *.test.* / *.spec.* files. */
  includeTests?: boolean;
  /** Report only findings in files changed since this git ref (the whole project is still scanned). */
  changedSince?: string;
}

const SCORE_COLOR_CHALK: Record<ScoreColor, (text: string) => string> = {
  green: chalk.bgGreen.black.bold,
  yellow: chalk.bgYellow.black.bold,
  red: chalk.bgRed.white.bold,
};

const SEVERITY_COLOR: Record<Severity, (text: string) => string> = {
  critical: chalk.bgRed.white.bold,
  high: chalk.red.bold,
  medium: chalk.yellow,
  low: chalk.gray,
};

function renderText(summary: ScanSummary): string {
  const lines: string[] = [];
  for (const result of summary.results) {
    if (result.parseError) {
      lines.push(chalk.yellow(`⚠  ${result.file}: ${result.parseError}`));
    }
    for (const finding of result.findings) {
      lines.push(renderFinding(finding));
    }
  }
  lines.push("");
  const outside = summary.filteredOutCount ? ` (+${summary.filteredOutCount} in unchanged files, not shown)` : "";
  const hidden = summary.suppressedCount ? ` (${summary.suppressedCount} hidden by security-hub-ignore comments)` : "";
  lines.push(
    chalk.bold(
      `Scanned ${summary.filesScanned} file(s) in ${summary.durationMs}ms — ${summary.findingsCount} finding(s)${outside}${hidden}.`,
    ),
  );

  const score = computeScore(summary);
  const badge = SCORE_COLOR_CHALK[score.color](` ${score.value}/100 — ${score.label} `);
  const breakdown =
    `critical ${score.bySeverity.critical} · high ${score.bySeverity.high} · ` +
    `medium ${score.bySeverity.medium} · low ${score.bySeverity.low}`;
  lines.push(`${badge}  ${chalk.dim(breakdown)}`);

  return lines.join("\n");
}

function renderFinding(finding: Finding): string {
  const color = SEVERITY_COLOR[finding.severity];
  const location = `${finding.location.file}:${finding.location.startLine}:${finding.location.startColumn}`;
  return [
    `${color(` ${finding.severity.toUpperCase()} `)} ${chalk.bold(finding.ruleId)}  ${chalk.dim(location)}`,
    `  ${finding.message}`,
    `  ${chalk.dim("sink:")} ${finding.sinkSnippet}`,
    "",
  ].join("\n");
}

function writeOutput(content: string, outFile?: string): void {
  if (!outFile) {
    process.stdout.write(content + "\n");
    return;
  }
  fs.writeFileSync(outFile, content, "utf8");
  process.stderr.write(chalk.green(`Written to ${path.resolve(outFile)}\n`));
}

const DEFAULT_HTML_REPORT_FILE = "security-report.html";

/** Runs a scan and prints/writes results. Returns the process exit code. */
export function runScan(targetPath: string, options: ScanCommandOptions): number {
  if (!fs.existsSync(targetPath)) {
    process.stderr.write(chalk.red(`Path not found: ${targetPath}\n`));
    return 2;
  }

  let changed: string[] | undefined;
  if (options.changedSince) {
    try {
      changed = changedFiles(fs.statSync(targetPath).isDirectory() ? targetPath : path.dirname(targetPath), options.changedSince);
    } catch (err) {
      process.stderr.write(chalk.red(`${(err as Error).message}\n`));
      return 2;
    }
  }

  // The scan always covers the whole project (a call in a changed file can reach a query in
  // an untouched one); --changed-since only narrows what is reported.
  const rawSummary = scanPath(targetPath, { ignore: options.ignore, includeTests: options.includeTests });
  const summary = filterSummary(rawSummary, { minSeverity: options.severity, files: changed });

  let output: string;
  let outFile = options.out;
  if (options.format === "sarif") {
    output = toSarifString(summary.results, { relativeTo: path.resolve(process.cwd()) });
  } else if (options.format === "json") {
    output = JSON.stringify({ ...summary, score: computeScore(summary) }, null, 2);
  } else if (options.format === "html") {
    output = toHtml(summary, targetPath);
    outFile = outFile ?? DEFAULT_HTML_REPORT_FILE; // always a file — printing raw HTML to a terminal isn't useful
  } else if (options.format === "markdown") {
    const scopeNote = changed ? `Only files changed since \`${options.changedSince}\` are listed (${changed.length} changed).` : undefined;
    output = toMarkdown(summary, { relativeTo: path.resolve(process.cwd()), scopeNote });
  } else if (options.format === "prompt") {
    output = toFixPrompt(summary, { relativeTo: path.resolve(process.cwd()) }) || "No findings: nothing to fix.";
  } else if (options.format === "github") {
    output = toGithubAnnotations(summary, { relativeTo: path.resolve(process.cwd()) }).join("\n");
  } else {
    output = renderText(summary);
  }

  writeOutput(output, outFile);

  if (options.failOn) {
    const threshold = SEVERITY_RANK[options.failOn];
    const hasBlockingFinding = summary.results.some((r) =>
      r.findings.some((f) => SEVERITY_RANK[f.severity] >= threshold),
    );
    if (hasBlockingFinding) return 1;
  }

  return 0;
}
