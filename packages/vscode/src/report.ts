// Everything the extension does that is not the editor's API: reading what `security-hub scan --format json --prompts` printed
// and turning it into plain items. Kept free of `vscode` imports so it is tested without an editor.
import * as path from "path";

export type Severity = "low" | "medium" | "high" | "critical";
export type Level = "error" | "warning" | "info";

export interface RawFinding {
  ruleId: string;
  severity: Severity;
  message: string;
  location: { file: string; startLine: number; startColumn: number; endLine: number; endColumn: number };
  fixPrompt?: string;
}

export interface RawReport {
  filesScanned: number;
  findingsCount: number;
  results: { file: string; findings: RawFinding[]; parseError?: string }[];
  score?: { value: number; color: "green" | "yellow" | "red"; label: string };
}

export interface Item {
  /** Absolute path. */
  file: string;
  /** 0-based, as the editor wants them. */
  line: number;
  column: number;
  endLine: number;
  endColumn: number;
  level: Level;
  severity: Severity;
  rule: string;
  message: string;
  prompt?: string;
}

const RANK: Record<Severity, number> = { low: 0, medium: 1, high: 2, critical: 3 };

/** The JSON document in the command's output. `npx` may print a line or two before it; anything after the closing brace is ignored. */
export function parseReport(stdout: string): RawReport {
  const start = stdout.indexOf("{");
  const end = stdout.lastIndexOf("}");
  if (start === -1 || end < start) throw new Error("The scanner printed no report. " + stdout.trim().split("\n").slice(-3).join(" ").slice(0, 300));
  const report = JSON.parse(stdout.slice(start, end + 1)) as Partial<RawReport>;
  if (!Array.isArray(report.results)) throw new Error("That is not a Security Testing Hub report (no results list).");
  return report as RawReport;
}

export function levelOf(severity: Severity): Level {
  if (severity === "critical" || severity === "high") return "error";
  return severity === "medium" ? "warning" : "info";
}

export function isSeverity(value: unknown): value is Severity {
  return value === "low" || value === "medium" || value === "high" || value === "critical";
}

/** The findings at or above `minimum`, with absolute paths (the scanner prints paths relative to where it ran: `root`). */
export function toItems(report: RawReport, root: string, minimum: Severity = "low"): Item[] {
  const items: Item[] = [];
  for (const result of report.results) {
    for (const finding of result.findings) {
      if (!isSeverity(finding.severity) || RANK[finding.severity] < RANK[minimum]) continue;
      const { location } = finding;
      const absolute = path.isAbsolute(location.file) ? location.file : path.resolve(root, location.file);
      items.push({
        file: absolute,
        line: Math.max(0, location.startLine - 1),
        column: Math.max(0, location.startColumn - 1),
        endLine: Math.max(0, location.endLine - 1),
        endColumn: Math.max(0, location.endColumn - 1),
        level: levelOf(finding.severity),
        severity: finding.severity,
        rule: finding.ruleId,
        message: finding.message,
        prompt: finding.fixPrompt,
      });
    }
  }
  return items;
}

/** The text of the status bar: `$(shield) 72/100`. */
export function statusText(report: RawReport, shown: number): string {
  const score = report.score ? `${report.score.value}/100` : "scanned";
  return `$(shield) ${score}${shown > 0 ? ` · ${shown}` : ""}`;
}

export function statusTooltip(report: RawReport, shown: number): string {
  const label = report.score ? `${report.score.label} (${report.score.value}/100). ` : "";
  return `Security Testing Hub: ${label}${shown} finding${shown === 1 ? "" : "s"} shown, ${report.filesScanned} files scanned. Click to scan again.`;
}

/** `npx --yes security-hub@latest` -> ["npx", "--yes", "security-hub@latest"]: split on spaces, quotes keep a path with spaces together. */
export function splitCommand(command: string): string[] {
  const parts: string[] = [];
  const pattern = /"([^"]*)"|'([^']*)'|(\S+)/g;
  for (let m = pattern.exec(command); m !== null; m = pattern.exec(command)) parts.push(m[1] ?? m[2] ?? (m[3] as string));
  return parts;
}
