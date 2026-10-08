import * as path from "path";
import { ScanSummary, Severity } from "./types";

export const SEVERITY_RANK: Record<Severity, number> = { low: 0, medium: 1, high: 2, critical: 3 };

export interface FilterOptions {
  /** Keep only findings at or above this severity. */
  minSeverity?: Severity;
  /** Keep only findings located in these files (absolute or relative paths). */
  files?: Iterable<string>;
}

/** Path form that compares equal for the same file however it was spelled (Windows is case-insensitive). */
export function comparablePath(file: string): string {
  const resolved = path.resolve(file);
  return process.platform === "win32" ? resolved.toLowerCase() : resolved;
}

/**
 * Narrows a scan to the findings you want to look at. The scan itself always covers the
 * whole project — a call in a changed file may reach a query in an unchanged one — only
 * the *report* is narrowed. `filteredOutCount` says how many findings were left out.
 */
export function filterSummary(summary: ScanSummary, options: FilterOptions): ScanSummary {
  const files = options.files ? new Set([...options.files].map(comparablePath)) : undefined;
  const threshold = options.minSeverity ? SEVERITY_RANK[options.minSeverity] : undefined;
  if (files === undefined && threshold === undefined) return summary;

  let filteredOut = 0;
  const results = summary.results.map((result) => {
    const inScope = files === undefined || files.has(comparablePath(result.file));
    const findings = result.findings.filter((finding) => {
      const keep = inScope && (threshold === undefined || SEVERITY_RANK[finding.severity] >= threshold);
      if (!keep && !inScope) filteredOut += 1;
      return keep;
    });
    return { ...result, findings };
  });

  return {
    ...summary,
    results,
    findingsCount: results.reduce((sum, r) => sum + r.findings.length, 0),
    filteredOutCount: (summary.filteredOutCount ?? 0) + filteredOut,
  };
}
