import * as fs from "fs";
import * as path from "path";
import chalk from "chalk";
import {
  scanPath,
  toSarifString,
  toHtml,
  computeScore,
  Finding,
  ScanSummary,
  Severity,
  ScoreColor,
} from "security-hub-scanner";

export interface ScanCommandOptions {
  format: "text" | "json" | "sarif" | "html";
  out?: string;
  severity?: Severity;
  failOn?: Severity;
}

const SCORE_COLOR_CHALK: Record<ScoreColor, (text: string) => string> = {
  green: chalk.bgGreen.black.bold,
  yellow: chalk.bgYellow.black.bold,
  red: chalk.bgRed.white.bold,
};

const SEVERITY_RANK: Record<Severity, number> = { low: 0, medium: 1, high: 2, critical: 3 };

const SEVERITY_COLOR: Record<Severity, (text: string) => string> = {
  critical: chalk.bgRed.white.bold,
  high: chalk.red.bold,
  medium: chalk.yellow,
  low: chalk.gray,
};

function filterBySeverity(summary: ScanSummary, minSeverity?: Severity): ScanSummary {
  if (!minSeverity) return summary;
  const threshold = SEVERITY_RANK[minSeverity];
  const results = summary.results.map((r) => ({
    ...r,
    findings: r.findings.filter((f) => SEVERITY_RANK[f.severity] >= threshold),
  }));
  return {
    ...summary,
    results,
    findingsCount: results.reduce((sum, r) => sum + r.findings.length, 0),
  };
}

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
  lines.push(
    chalk.bold(
      `Scanned ${summary.filesScanned} file(s) in ${summary.durationMs}ms — ${summary.findingsCount} finding(s).`,
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

  const rawSummary = scanPath(targetPath);
  const summary = filterBySeverity(rawSummary, options.severity);

  let output: string;
  let outFile = options.out;
  if (options.format === "sarif") {
    output = toSarifString(summary.results);
  } else if (options.format === "json") {
    output = JSON.stringify({ ...summary, score: computeScore(summary) }, null, 2);
  } else if (options.format === "html") {
    output = toHtml(summary, targetPath);
    outFile = outFile ?? DEFAULT_HTML_REPORT_FILE; // always a file — printing raw HTML to a terminal isn't useful
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
