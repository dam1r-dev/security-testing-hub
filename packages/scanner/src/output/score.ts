import { ScanSummary, Severity, Finding } from "../types";

export type ScoreColor = "green" | "yellow" | "red";

export interface SecurityScore {
  /** 0-100, rounded. 100 = no findings at all. */
  value: number;
  color: ScoreColor;
  label: "Good" | "Needs attention" | "At risk";
  bySeverity: Record<Severity, number>;
  totalFindings: number;
  /**
   * False when no source code was analysed at all (an empty folder, a project in a language without rules, a wrong path): the value
   * is then 100 only because nothing was looked at, and every report says "not rated" instead of "Good".
   */
  rated: boolean;
}

// Higher severity costs more; a handful of criticals should visibly hurt the
// score, a pile of lows shouldn't tank it the same way one SQLi would.
const SEVERITY_WEIGHT: Record<Severity, number> = {
  critical: 20,
  high: 10,
  medium: 4,
  low: 1,
};

// Our heuristic rules (CSRF/IDOR/broken-access-control/...) report their own
// confidence — a "low confidence" route-heuristic finding shouldn't cost the
// same as a "medium confidence" taint-tracked SQL injection. This keeps the
// score honest about how sure we actually are, instead of pretending every
// finding is equally certain.
const CONFIDENCE_MULTIPLIER: Record<Finding["confidence"], number> = {
  high: 1,
  medium: 0.7,
  low: 0.4,
};

function colorFor(value: number): ScoreColor {
  if (value >= 80) return "green";
  if (value >= 50) return "yellow";
  return "red";
}

function labelFor(color: ScoreColor): SecurityScore["label"] {
  if (color === "green") return "Good";
  if (color === "yellow") return "Needs attention";
  return "At risk";
}

/**
 * A single 0-100 number summarizing scan results, so results are skimmable
 * without reading every finding. This is necessarily a simplification (see
 * README.md#scope--limitations on false positives) — treat it as a rough
 * signal for "did this get worse/better", not a certification.
 */
export function computeScore(summary: ScanSummary): SecurityScore {
  const bySeverity: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0 };
  let penalty = 0;
  let totalFindings = 0;

  for (const result of summary.results) {
    for (const finding of result.findings) {
      totalFindings += 1;
      bySeverity[finding.severity] += 1;
      penalty += SEVERITY_WEIGHT[finding.severity] * CONFIDENCE_MULTIPLIER[finding.confidence];
    }
  }

  const value = Math.max(0, Math.min(100, Math.round(100 - penalty)));
  const color = colorFor(value);

  const rated = summary.coverage ? summary.coverage.analyzed > 0 : true;
  return { value, color, label: labelFor(color), bySeverity, totalFindings, rated };
}

function count(n: number, noun: string): string {
  return `${n} ${noun}${n === 1 ? "" : "s"}`;
}

/**
 * What a clean report does not cover, in plain sentences (empty when the scan read everything it found). Shown by every output format:
 * a score of 100 means "no findings in the code that was read", and these lines say how much of the project that was.
 */
export function coverageNotes(summary: ScanSummary): string[] {
  const c = summary.coverage;
  if (!c) return [];
  const notes: string[] = [];
  const languages = Object.entries(c.unsupported).sort((a, b) => b[1] - a[1]);
  const unsupportedTotal = languages.reduce((sum, [, n]) => sum + n, 0);
  const list = languages.map(([name, n]) => `${name} ${n}`).join(", ");
  if (c.analyzed === 0) {
    notes.push(
      unsupportedTotal > 0
        ? `No JavaScript, TypeScript, Python or PHP source was analysed, so nothing in this project's code was checked. Found ${count(unsupportedTotal, "file")} in languages without rules (${list}).`
        : "No JavaScript, TypeScript, Python or PHP source was analysed, so nothing in this project's code was checked. Check the path, and --ignore / .security-hub-ignore.",
    );
  } else if (unsupportedTotal > 0) {
    notes.push(`${count(unsupportedTotal, "file")} in languages without rules were not checked (${list}); this report covers the ${count(c.analyzed, "JavaScript, TypeScript, Python or PHP file")} that ${c.analyzed === 1 ? "was" : "were"} analysed.`);
  }
  if (c.skipped > 0) notes.push(`${count(c.skipped, "file")} skipped (minified or bundled, a third-party library, over the size limit, or unreadable); each is listed with its reason.`);
  if (c.parseErrors > 0) notes.push(`${count(c.parseErrors, "file")} could not be parsed completely, so results for ${c.parseErrors === 1 ? "it" : "them"} may be incomplete.`);
  return notes;
}
