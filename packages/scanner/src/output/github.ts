import * as path from "path";
import { Finding, ScanSummary, Severity } from "../types";

export interface GithubAnnotationOptions {
  /** Paths must be relative to the repository root; usually the workspace folder. */
  relativeTo: string;
}

const LEVEL: Record<Severity, "error" | "warning" | "notice"> = {
  critical: "error",
  high: "error",
  medium: "warning",
  low: "notice",
};

// https://docs.github.com/actions/reference/workflow-commands-for-github-actions
// Finding text comes from scanned code, so it must never be able to start another workflow
// command: newlines are always escaped, and so are the characters that delimit properties.
function escapeData(value: string): string {
  return value.replace(/%/g, "%25").replace(/\r/g, "%0D").replace(/\n/g, "%0A");
}

function escapeProperty(value: string): string {
  return escapeData(value).replace(/:/g, "%3A").replace(/,/g, "%2C");
}

export function annotationFor(finding: Finding, options: GithubAnnotationOptions): string {
  const file = path.relative(options.relativeTo, finding.location.file).split(path.sep).join("/");
  const properties = [
    `file=${escapeProperty(file)}`,
    `line=${finding.location.startLine}`,
    `col=${finding.location.startColumn}`,
    `endLine=${finding.location.endLine}`,
    `title=${escapeProperty(`${finding.ruleId} (${finding.severity})`)}`,
  ].join(",");
  return `::${LEVEL[finding.severity]} ${properties}::${escapeData(finding.message)}`;
}

/** One `::error` / `::warning` / `::notice` line per finding: GitHub shows them inline in the pull request diff. */
export function toGithubAnnotations(summary: ScanSummary, options: GithubAnnotationOptions): string[] {
  return summary.results.flatMap((r) => r.findings).map((finding) => annotationFor(finding, options));
}
