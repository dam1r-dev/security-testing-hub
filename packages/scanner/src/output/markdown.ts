import * as path from "path";
import { Finding, ScanSummary, Severity } from "../types";
import { fenced, toFixPrompt } from "./fix-prompt";
import { computeScore } from "./score";

/** Hidden marker so a bot can find and update its own comment instead of posting a new one each push. */
export const MARKDOWN_MARKER = "<!-- security-testing-hub-report -->";

export interface MarkdownOptions {
  /** Display paths relative to this folder (default: absolute as scanned). */
  relativeTo?: string;
  /** Link each location to `<linkBase>/<path>#L<line>`, e.g. https://github.com/o/r/blob/<sha>. */
  linkBase?: string;
  /** Rows shown before "...and N more" (default 25). */
  maxRows?: number;
  /** Shown above the table, e.g. "Only files changed in this pull request are listed." */
  scopeNote?: string;
  /** Add a collapsed "prompt for your AI assistant" block (default true). */
  fixPrompt?: boolean;
}

const SEVERITY_ICON: Record<Severity, string> = { critical: "🟥", high: "🟧", medium: "🟨", low: "⬜" };
const SCORE_ICON = { green: "🟢", yellow: "🟡", red: "🔴" } as const;

// Finding text can contain code and file names from the pull request, i.e. attacker-controlled
// text going into a comment on the maintainers' page: neutralise markdown, HTML and @-mentions.
function escapeMarkdown(text: string): string {
  return text.replace(/[\\`*_[\]<>|~&@#]/g, (ch) => (ch === "&" ? "&amp;" : ch === "<" ? "&lt;" : ch === ">" ? "&gt;" : `\\${ch}`));
}

function codeSpan(text: string): string {
  return `\`${text.replace(/[`\r\n]/g, " ")}\``;
}

function firstSentence(message: string): string {
  const match = /^(.*?[.!?])(\s|$)/.exec(message);
  const sentence = (match?.[1] ?? message).trim();
  return sentence.length > 220 ? `${sentence.slice(0, 217)}...` : sentence;
}

/** "...reaches the vulnerable call at services/x.js:8 (via a -> b)." -> "services/x.js:8" */
function crossFileTarget(message: string): string | undefined {
  return /reaches the vulnerable call at (\S+?)(?: \(via [^)]*\))?\.\s*$/.exec(message)?.[1];
}

function locationCell(finding: Finding, options: MarkdownOptions): string {
  const file = options.relativeTo ? path.relative(options.relativeTo, finding.location.file) : finding.location.file;
  const normalized = file.split(path.sep).join("/");
  const label = codeSpan(`${normalized}:${finding.location.startLine}`);
  if (!options.linkBase) return label;
  const encoded = normalized.split("/").map(encodeURIComponent).join("/");
  return `[${label}](${options.linkBase.replace(/\/$/, "")}/${encoded}#L${finding.location.startLine})`;
}

export function toMarkdown(summary: ScanSummary, options: MarkdownOptions = {}): string {
  const score = computeScore(summary);
  const findings = summary.results.flatMap((r) => r.findings);
  const maxRows = options.maxRows ?? 25;
  const lines: string[] = [MARKDOWN_MARKER, "", `## 🛡️ Security Testing Hub: ${SCORE_ICON[score.color]} ${score.value}/100 (${score.label})`, ""];

  const counts =
    `critical **${score.bySeverity.critical}** · high **${score.bySeverity.high}** · ` +
    `medium **${score.bySeverity.medium}** · low **${score.bySeverity.low}**`;
  lines.push(findings.length === 0 ? "No findings. 🎉" : counts, "");

  const notes: string[] = [];
  if (options.scopeNote) notes.push(options.scopeNote);
  if (summary.filteredOutCount) notes.push(`${summary.filteredOutCount} more finding(s) in files this change does not touch are not listed.`);
  if (summary.suppressedCount) notes.push(`${summary.suppressedCount} finding(s) hidden by \`security-hub-ignore\` comments.`);
  for (const note of notes) lines.push(`> ${note}`);
  if (notes.length > 0) lines.push("");

  if (findings.length > 0) {
    const ordered = [...findings].sort((a, b) => ["critical", "high", "medium", "low"].indexOf(a.severity) - ["critical", "high", "medium", "low"].indexOf(b.severity));
    lines.push("| | Rule | Where | What |", "|---|---|---|---|");
    for (const finding of ordered.slice(0, maxRows)) {
      const target = crossFileTarget(finding.message);
      const what = escapeMarkdown(firstSentence(finding.message)) + (target ? ` → ${codeSpan(target)}` : "");
      lines.push(
        `| ${SEVERITY_ICON[finding.severity]} ${finding.severity} | ${codeSpan(finding.ruleId)} | ${locationCell(finding, options)} | ${what} |`,
      );
    }
    if (ordered.length > maxRows) lines.push("", `…and ${ordered.length - maxRows} more.`);
    lines.push("");

    if (options.fixPrompt !== false) {
      // The prompt sits in a code fence: nothing inside it is rendered as markdown/HTML or can ping anyone.
      const prompt = toFixPrompt(summary, { relativeTo: options.relativeTo, maxFindings: 10 });
      lines.push(
        "<details><summary>🤖 Fix with AI: copy this prompt into Cursor / Claude / Copilot</summary>",
        "",
        fenced(prompt),
        "",
        "</details>",
        "",
      );
    }
  }

  lines.push(
    "<sub>Heuristic static analysis: a helper, not a replacement for security review. " +
      "Wrong finding? Add `// security-hub-ignore` above it. " +
      "[Security Testing Hub](https://github.com/dam1r-dev/security-testing-hub)</sub>",
  );
  return lines.join("\n");
}
