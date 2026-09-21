import * as fs from "fs";
import * as path from "path";
import chalk from "chalk";
import { scanPath, toSarifString, Finding, ScanSummary, Severity } from "@security-hub/scanner";

export interface ScanCommandOptions {
  format: "text" | "json" | "sarif";
  out?: string;
  severity?: Severity;
  failOn?: Severity;
}

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

/** Runs a scan and prints/writes results. Returns the process exit code. */
export function runScan(targetPath: string, options: ScanCommandOptions): number {
  if (!fs.existsSync(targetPath)) {
    process.stderr.write(chalk.red(`Path not found: ${targetPath}\n`));
    return 2;
  }

  const rawSummary = scanPath(targetPath);
  const summary = filterBySeverity(rawSummary, options.severity);

  const output =
    options.format === "sarif"
      ? toSarifString(summary.results)
      : options.format === "json"
        ? JSON.stringify(summary, null, 2)
        : renderText(summary);

  writeOutput(output, options.out);

  if (options.failOn) {
    const threshold = SEVERITY_RANK[options.failOn];
    const hasBlockingFinding = summary.results.some((r) =>
      r.findings.some((f) => SEVERITY_RANK[f.severity] >= threshold),
    );
    if (hasBlockingFinding) return 1;
  }

  return 0;
}
