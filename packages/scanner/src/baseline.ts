import { createHash } from "crypto";
import * as fs from "fs";
import * as path from "path";
import { Finding, ScanSummary } from "./types";

/**
 * A baseline lets a project that already has findings start using the scanner today: it records what is there now, and
 * later scans report only what is NEW. It is the way to turn the tool on in an old codebase and fail pull requests on
 * new problems without fixing every old one first.
 *
 * Findings are matched by a fingerprint that survives edits elsewhere in the file: the rule, the file, and the flagged
 * line's text with whitespace collapsed; the line NUMBER is not part of it (it changes with every edit above). The
 * same line flagged twice gets two entries, so adding a third copy is still new. A hard-coded secret is matched by the
 * NAME it was assigned to, never by its value: a hash of a weak secret in a committed file could be brute-forced.
 *
 * Nothing is silent: a scan says how many findings the baseline hid and how many entries no longer match (fixed or
 * moved), and the baseline file is an ordinary file in the repository, reviewed like any other change.
 */
export const BASELINE_FILE_NAME = ".security-hub-baseline.json";

export interface BaselineEntry {
  /** The fingerprint (and, for a repeated line, which occurrence). */
  id: string;
  rule: string;
  file: string;
  /** Only to help a person reading the file; matching never uses it. */
  line: number;
}

export interface Baseline {
  version: 1;
  findings: BaselineEntry[];
}

function stripByteOrderMark(text: string): string {
  return text.charCodeAt(0) === 0xfeff ? text.slice(1) : text;
}

export class BaselineError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "BaselineError";
  }
}

function relativeFile(finding: Finding, root: string): string {
  return path.relative(root, finding.location.file).split(path.sep).join("/");
}

function fingerprint(finding: Finding, file: string): string {
  let basis: string;
  if (finding.ruleId === "hardcoded-secret") {
    basis = /`([^`]+)`/.exec(finding.message)?.[1] ?? ""; // the name of the variable or property, never any part of the value
  } else {
    basis = finding.sinkSnippet.replace(/\s+/g, " ").trim() || finding.message;
  }
  return createHash("sha256").update(`${finding.ruleId}\n${file}\n${basis}`).digest("hex").slice(0, 16);
}

/** One id per finding: the fingerprint plus `.2`, `.3` for the same line flagged again in the same file. */
function identify(summary: ScanSummary, root: string): { finding: Finding; entry: BaselineEntry }[] {
  const all = summary.results
    .flatMap((r) => r.findings)
    .map((finding) => ({ finding, file: relativeFile(finding, root) }))
    .sort((a, b) => a.file.localeCompare(b.file) || a.finding.location.startLine - b.finding.location.startLine || a.finding.location.startColumn - b.finding.location.startColumn);
  const seen = new Map<string, number>();
  return all.map(({ finding, file }) => {
    const base = fingerprint(finding, file);
    const n = (seen.get(base) ?? 0) + 1;
    seen.set(base, n);
    return { finding, entry: { id: n === 1 ? base : `${base}.${n}`, rule: finding.ruleId, file, line: finding.location.startLine } };
  });
}

/** What a scan holds right now, as a baseline file. */
export function createBaseline(summary: ScanSummary, root: string): Baseline {
  return { version: 1, findings: identify(summary, path.resolve(root)).map((x) => x.entry) };
}

export function serializeBaseline(baseline: Baseline): string {
  return JSON.stringify(baseline, null, 2) + "\n";
}

export function parseBaseline(text: string, source: string = BASELINE_FILE_NAME): Baseline {
  let raw: unknown;
  try {
    raw = JSON.parse(stripByteOrderMark(text));
  } catch (err) {
    throw new BaselineError(`${source}: not valid JSON (${(err as Error).message}). Recreate it with: security-hub baseline`);
  }
  const object = raw as { version?: unknown; findings?: unknown } | null;
  if (typeof object !== "object" || object === null || object.version !== 1 || !Array.isArray(object.findings)) {
    throw new BaselineError(`${source}: not a baseline file (version 1 with a "findings" list). Recreate it with: security-hub baseline`);
  }
  const findings: BaselineEntry[] = [];
  for (const item of object.findings as unknown[]) {
    const entry = item as Partial<BaselineEntry> | null;
    if (typeof entry !== "object" || entry === null || typeof entry.id !== "string" || !/^[0-9a-f]{16}(?:\.\d+)?$/.test(entry.id)) {
      throw new BaselineError(`${source}: an entry has no valid "id". Recreate it with: security-hub baseline`);
    }
    findings.push({ id: entry.id, rule: String(entry.rule ?? ""), file: String(entry.file ?? ""), line: Number(entry.line) || 0 });
  }
  return { version: 1, findings };
}

/** The baseline named by `explicitFile`, or `.security-hub-baseline.json` in `directory` when there is one. */
export function loadBaseline(directory: string, explicitFile?: string): { baseline: Baseline; file: string } | undefined {
  const file = explicitFile ? path.resolve(explicitFile) : path.join(directory, BASELINE_FILE_NAME);
  let text: string;
  try {
    text = fs.readFileSync(file, "utf8");
  } catch {
    if (explicitFile) throw new BaselineError(`Baseline file not found: ${explicitFile}`);
    return undefined;
  }
  return { baseline: parseBaseline(text, path.basename(file)), file };
}

/**
 * The summary without the findings the baseline already knows. `baselinedCount` is how many were hidden;
 * `staleBaselineCount` how many entries matched nothing (the problem was fixed, or the line was rewritten).
 */
export function applyBaseline(summary: ScanSummary, baseline: Baseline, root: string): ScanSummary {
  const known = new Set(baseline.findings.map((e) => e.id));
  const identified = identify(summary, path.resolve(root));
  const hidden = new Set<Finding>();
  const matched = new Set<string>();
  for (const { finding, entry } of identified) {
    if (known.has(entry.id)) {
      hidden.add(finding);
      matched.add(entry.id);
    }
  }
  const results = summary.results.map((r) => ({ ...r, findings: r.findings.filter((f) => !hidden.has(f)) }));
  return {
    ...summary,
    results,
    findingsCount: results.reduce((sum, r) => sum + r.findings.length, 0),
    baselinedCount: (summary.baselinedCount ?? 0) + hidden.size,
    staleBaselineCount: baseline.findings.filter((e) => !matched.has(e.id)).length,
  };
}
