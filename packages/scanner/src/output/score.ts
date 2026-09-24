import { ScanSummary, Severity, Finding } from "../types";

export type ScoreColor = "green" | "yellow" | "red";

export interface SecurityScore {
  /** 0-100, rounded. 100 = no findings at all. */
  value: number;
  color: ScoreColor;
  label: "Good" | "Needs attention" | "At risk";
  bySeverity: Record<Severity, number>;
  totalFindings: number;
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

  return { value, color, label: labelFor(color), bySeverity, totalFindings };
}
