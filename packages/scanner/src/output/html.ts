import { Finding, ScanSummary, Severity } from "../types";
import { computeScore, ScoreColor } from "./score";

const COLOR_HEX: Record<ScoreColor, { main: string; bg: string; ring: string }> = {
  green: { main: "#16a34a", bg: "#f0fdf4", ring: "#16a34a" },
  yellow: { main: "#ca8a04", bg: "#fefce8", ring: "#ca8a04" },
  red: { main: "#dc2626", bg: "#fef2f2", ring: "#dc2626" },
};

const SEVERITY_COLOR: Record<Severity, string> = {
  critical: "#7f1d1d",
  high: "#dc2626",
  medium: "#ca8a04",
  low: "#6b7280",
};

function escapeHtml(text: string): string {
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function scoreRingSvg(value: number, color: ScoreColor): string {
  const radius = 70;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference * (1 - value / 100);
  const hex = COLOR_HEX[color];
  return `
    <svg width="180" height="180" viewBox="0 0 180 180" class="score-ring" role="img" aria-label="Security score ${value} out of 100">
      <circle cx="90" cy="90" r="${radius}" fill="none" stroke="#e5e7eb" stroke-width="14" />
      <circle cx="90" cy="90" r="${radius}" fill="none" stroke="${hex.ring}" stroke-width="14"
        stroke-linecap="round" stroke-dasharray="${circumference}" stroke-dashoffset="${offset}"
        transform="rotate(-90 90 90)" />
      <text x="90" y="82" text-anchor="middle" class="score-value" fill="${hex.main}">${value}</text>
      <text x="90" y="108" text-anchor="middle" class="score-percent" fill="${hex.main}">/ 100</text>
    </svg>`;
}

function findingCard(finding: Finding): string {
  const loc = finding.location;
  return `
    <article class="finding" data-severity="${finding.severity}">
      <div class="finding-head">
        <span class="badge" style="background:${SEVERITY_COLOR[finding.severity]}">${finding.severity.toUpperCase()}</span>
        <span class="rule-id">${escapeHtml(finding.ruleId)}</span>
        <span class="confidence">confidence: ${finding.confidence}</span>
      </div>
      <p class="message">${escapeHtml(finding.message)}</p>
      <div class="location">${escapeHtml(loc.file)}:${loc.startLine}:${loc.startColumn}</div>
      <pre class="snippet"><code>${escapeHtml(finding.sinkSnippet)}</code></pre>
    </article>`;
}

/** Renders a self-contained, single-file HTML report — no server, no external assets. */
export function toHtml(summary: ScanSummary, targetPath?: string): string {
  const score = computeScore(summary);
  const hex = COLOR_HEX[score.color];
  const allFindings = summary.results.flatMap((r) => r.findings);
  const parseWarnings = summary.results.filter((r) => r.parseError);

  const findingsHtml =
    allFindings.length > 0
      ? allFindings.map(findingCard).join("\n")
      : `<p class="empty-state">No findings — nice work. Remember this is a heuristic scanner (see the README's false-negative caveats), not a guarantee.</p>`;

  const generatedAt = new Date().toISOString();

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Security Testing Hub — Scan Report</title>
<style>
  :root { color-scheme: light; }
  * { box-sizing: border-box; }
  body {
    margin: 0; padding: 32px 16px 64px;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    background: #f8fafc; color: #0f172a;
  }
  .container { max-width: 920px; margin: 0 auto; }
  header { margin-bottom: 24px; }
  h1 { font-size: 22px; margin: 0 0 4px; }
  .subtitle { color: #64748b; font-size: 14px; }
  .score-card {
    display: flex; align-items: center; gap: 28px; flex-wrap: wrap;
    background: ${hex.bg}; border: 1px solid ${hex.main}33; border-radius: 16px;
    padding: 24px; margin-bottom: 24px;
  }
  .score-ring .score-value { font-size: 40px; font-weight: 700; }
  .score-ring .score-percent { font-size: 13px; opacity: 0.8; }
  .score-meta { flex: 1; min-width: 220px; }
  .score-label { font-size: 20px; font-weight: 700; color: ${hex.main}; margin: 0 0 4px; }
  .score-sub { color: #475569; font-size: 14px; margin: 0 0 12px; }
  .stat-row { display: flex; gap: 16px; flex-wrap: wrap; }
  .stat { background: #fff; border-radius: 10px; padding: 8px 14px; border: 1px solid #e2e8f0; min-width: 84px; }
  .stat .n { font-size: 20px; font-weight: 700; display: block; }
  .stat .l { font-size: 11px; color: #64748b; text-transform: uppercase; letter-spacing: 0.04em; }
  .filters { display: flex; gap: 8px; margin: 20px 0 12px; flex-wrap: wrap; }
  .filters button {
    border: 1px solid #cbd5e1; background: #fff; border-radius: 999px; padding: 6px 14px;
    font-size: 13px; cursor: pointer; color: #334155;
  }
  .filters button.active { background: #0f172a; color: #fff; border-color: #0f172a; }
  .finding {
    background: #fff; border: 1px solid #e2e8f0; border-radius: 12px;
    padding: 16px 18px; margin-bottom: 12px;
  }
  .finding-head { display: flex; align-items: center; gap: 10px; margin-bottom: 8px; flex-wrap: wrap; }
  .badge { color: #fff; font-size: 11px; font-weight: 700; padding: 3px 8px; border-radius: 999px; letter-spacing: 0.03em; }
  .rule-id { font-weight: 700; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
  .confidence { font-size: 12px; color: #94a3b8; margin-left: auto; }
  .message { margin: 0 0 8px; font-size: 14px; line-height: 1.5; }
  .location { font-size: 12px; color: #64748b; font-family: ui-monospace, monospace; margin-bottom: 8px; }
  .snippet {
    background: #0f172a; color: #e2e8f0; padding: 10px 12px; border-radius: 8px;
    font-size: 12px; overflow-x: auto; margin: 0;
  }
  .empty-state { color: #16a34a; font-weight: 600; }
  .parse-warnings { margin: 20px 0; font-size: 13px; color: #92400e; background: #fffbeb; border: 1px solid #fde68a; border-radius: 10px; padding: 12px 16px; }
  .parse-warnings summary { cursor: pointer; font-weight: 600; }
  footer { margin-top: 40px; font-size: 12px; color: #94a3b8; text-align: center; }
  footer a { color: #64748b; }
</style>
</head>
<body>
<div class="container">
  <header>
    <h1>Security Testing Hub — Scan Report</h1>
    <div class="subtitle">${targetPath ? escapeHtml(targetPath) : "scan"} · ${summary.filesScanned} file(s) · ${summary.durationMs}ms · generated ${generatedAt}</div>
  </header>

  <div class="score-card">
    ${scoreRingSvg(score.value, score.color)}
    <div class="score-meta">
      <p class="score-label">${score.label}</p>
      <p class="score-sub">${score.totalFindings} finding(s) across ${summary.filesScanned} scanned file(s). This score is a rough heuristic signal, not a certification — see the README for known false-positive/false-negative rates.</p>
      <div class="stat-row">
        <div class="stat" style="border-color:${SEVERITY_COLOR.critical}55"><span class="n" style="color:${SEVERITY_COLOR.critical}">${score.bySeverity.critical}</span><span class="l">Critical</span></div>
        <div class="stat" style="border-color:${SEVERITY_COLOR.high}55"><span class="n" style="color:${SEVERITY_COLOR.high}">${score.bySeverity.high}</span><span class="l">High</span></div>
        <div class="stat" style="border-color:${SEVERITY_COLOR.medium}55"><span class="n" style="color:${SEVERITY_COLOR.medium}">${score.bySeverity.medium}</span><span class="l">Medium</span></div>
        <div class="stat" style="border-color:${SEVERITY_COLOR.low}55"><span class="n" style="color:${SEVERITY_COLOR.low}">${score.bySeverity.low}</span><span class="l">Low</span></div>
      </div>
    </div>
  </div>

  ${
    parseWarnings.length > 0
      ? `<details class="parse-warnings"><summary>${parseWarnings.length} file(s) had parse issues (results may be incomplete for them)</summary><ul>${parseWarnings
          .map((r) => `<li>${escapeHtml(r.file)}: ${escapeHtml(r.parseError ?? "")}</li>`)
          .join("")}</ul></details>`
      : ""
  }

  <div class="filters" id="filters">
    <button data-filter="all" class="active">All (${allFindings.length})</button>
    <button data-filter="critical">Critical (${score.bySeverity.critical})</button>
    <button data-filter="high">High (${score.bySeverity.high})</button>
    <button data-filter="medium">Medium (${score.bySeverity.medium})</button>
    <button data-filter="low">Low (${score.bySeverity.low})</button>
  </div>

  <div id="findings">
    ${findingsHtml}
  </div>

  <footer>
    Generated by <a href="https://github.com/dam1r-dev/security-testing-hub">Security Testing Hub</a>.
    Heuristic static analysis — a helper, not a replacement for security review.
  </footer>
</div>
<script>
  (function () {
    var buttons = document.querySelectorAll('#filters button');
    var cards = document.querySelectorAll('.finding');
    buttons.forEach(function (btn) {
      btn.addEventListener('click', function () {
        buttons.forEach(function (b) { b.classList.remove('active'); });
        btn.classList.add('active');
        var filter = btn.getAttribute('data-filter');
        cards.forEach(function (card) {
          card.style.display = filter === 'all' || card.getAttribute('data-severity') === filter ? '' : 'none';
        });
      });
    });
  })();
</script>
</body>
</html>`;
}
