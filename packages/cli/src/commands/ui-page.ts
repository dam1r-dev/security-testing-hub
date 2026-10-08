export interface UiPageOptions {
  /** Per-run secret the page must send back with every API call. */
  token: string;
  /** CSP nonce for the single inline <script>. */
  nonce: string;
  /** Folder shown in the input when the page opens. */
  initialPath: string;
  /** True when the user passed a path on the command line (then it beats the remembered one). */
  explicitPath: boolean;
  version: string;
}

function escapeAttr(text: string): string {
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

// The page is a single self-contained document: no external fonts, scripts or
// images (the server's CSP forbids them anyway). All scan data is inserted with
// textContent — never innerHTML — because findings contain code from the
// scanned project, which must not be able to run in this page.
export function renderUiPage(options: UiPageOptions): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<meta name="token" content="${escapeAttr(options.token)}" />
<meta name="initial-path" content="${escapeAttr(options.initialPath)}" data-explicit="${options.explicitPath ? "1" : "0"}" />
<title>Security Testing Hub</title>
<style>
  * { box-sizing: border-box; }
  body {
    margin: 0; padding: 28px 16px 64px;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    background: #f8fafc; color: #0f172a;
  }
  .container { max-width: 920px; margin: 0 auto; }
  .topbar { display: flex; align-items: flex-start; justify-content: space-between; gap: 12px; flex-wrap: wrap; }
  h1 { font-size: 24px; margin: 0 0 4px; }
  .subtitle { color: #64748b; font-size: 14px; margin: 0; }
  .langs button { border: 1px solid #cbd5e1; background: #fff; padding: 4px 10px; font-size: 12px; cursor: pointer; color: #334155; }
  .langs button:first-child { border-radius: 8px 0 0 8px; }
  .langs button:last-child { border-radius: 0 8px 8px 0; }
  .langs button + button { border-left: none; }
  .langs button.active { background: #0f172a; color: #fff; border-color: #0f172a; }
  .panel { background: #fff; border: 1px solid #e2e8f0; border-radius: 14px; padding: 20px; margin-top: 20px; }
  label.field { display: block; font-size: 13px; font-weight: 600; margin-bottom: 8px; color: #334155; }
  .row { display: flex; gap: 8px; flex-wrap: wrap; }
  .row input[type=text] {
    flex: 1; min-width: 220px; padding: 10px 12px; font-size: 14px; border: 1px solid #cbd5e1;
    border-radius: 10px; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  }
  button.btn { border: 1px solid #cbd5e1; background: #fff; color: #0f172a; border-radius: 10px; padding: 10px 16px; font-size: 14px; cursor: pointer; }
  button.btn:hover { background: #f1f5f9; }
  button.primary { background: #0f172a; color: #fff; border-color: #0f172a; font-weight: 600; }
  button.primary:hover { background: #1e293b; }
  button.btn:disabled { opacity: 0.55; cursor: default; }
  .privacy { margin: 12px 0 0; font-size: 12px; color: #64748b; }
  .error { margin-top: 14px; padding: 10px 14px; border-radius: 10px; background: #fef2f2; color: #991b1b; border: 1px solid #fecaca; font-size: 14px; }
  .hidden { display: none !important; }

  .score-card { display: flex; align-items: center; gap: 28px; flex-wrap: wrap; border-radius: 16px; padding: 24px; margin-top: 20px; border: 1px solid; }
  .ring { --v: 0; --c: #16a34a; width: 150px; height: 150px; border-radius: 50%; flex: none;
    background: conic-gradient(var(--c) calc(var(--v) * 1%), #e5e7eb 0); display: grid; place-items: center; }
  .ring-inner { width: 118px; height: 118px; border-radius: 50%; background: #fff; display: flex; flex-direction: column; align-items: center; justify-content: center; }
  .ring-value { font-size: 38px; font-weight: 700; line-height: 1; }
  .ring-max { font-size: 12px; color: #64748b; margin-top: 2px; }
  .score-meta { flex: 1; min-width: 220px; }
  .score-label { font-size: 22px; font-weight: 700; margin: 0 0 4px; }
  .score-sub { margin: 0 0 12px; font-size: 14px; color: #475569; }
  .stat-row { display: flex; gap: 10px; flex-wrap: wrap; }
  .stat { background: #fff; border-radius: 10px; padding: 8px 14px; border: 1px solid #e2e8f0; min-width: 84px; }
  .stat .n { font-size: 20px; font-weight: 700; display: block; }
  .stat .l { font-size: 11px; color: #64748b; text-transform: uppercase; letter-spacing: 0.04em; }

  .toolbar { display: flex; gap: 8px; margin: 22px 0 12px; flex-wrap: wrap; align-items: center; }
  .toolbar .spacer { flex: 1; }
  .chip { border: 1px solid #cbd5e1; background: #fff; border-radius: 999px; padding: 6px 14px; font-size: 13px; cursor: pointer; color: #334155; }
  .chip.active { background: #0f172a; color: #fff; border-color: #0f172a; }
  .finding { background: #fff; border: 1px solid #e2e8f0; border-radius: 12px; padding: 16px 18px; margin-bottom: 12px; }
  .finding-head { display: flex; align-items: center; gap: 10px; margin-bottom: 8px; flex-wrap: wrap; }
  .badge { color: #fff; font-size: 11px; font-weight: 700; padding: 3px 8px; border-radius: 999px; letter-spacing: 0.03em; text-transform: uppercase; }
  .rule-id { font-weight: 700; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
  .confidence { font-size: 12px; color: #94a3b8; margin-left: auto; }
  .message { margin: 0 0 8px; font-size: 14px; line-height: 1.5; }
  .location { font-size: 12px; color: #64748b; font-family: ui-monospace, monospace; margin-bottom: 8px; word-break: break-all; }
  .snippet { background: #0f172a; color: #e2e8f0; padding: 10px 12px; border-radius: 8px; font-size: 12px; overflow-x: auto; margin: 0; white-space: pre-wrap; word-break: break-word; }
  .btn.small { padding: 5px 10px; font-size: 12px; margin-top: 10px; }
  .empty-state { color: #16a34a; font-weight: 600; }
  .warn { margin-top: 16px; font-size: 13px; color: #92400e; background: #fffbeb; border: 1px solid #fde68a; border-radius: 10px; padding: 12px 16px; }

  .modal-backdrop { position: fixed; inset: 0; background: rgba(15, 23, 42, 0.5); display: flex; align-items: center; justify-content: center; padding: 16px; }
  .modal { background: #fff; border-radius: 14px; width: 100%; max-width: 640px; max-height: 85vh; display: flex; flex-direction: column; overflow: hidden; }
  .modal-head { padding: 14px 16px; border-bottom: 1px solid #e2e8f0; }
  .modal-path { font-family: ui-monospace, monospace; font-size: 13px; word-break: break-all; margin-top: 8px; color: #334155; }
  .roots { display: flex; gap: 6px; flex-wrap: wrap; }
  .roots button { font-size: 12px; padding: 4px 10px; }
  .modal-list { overflow-y: auto; flex: 1; padding: 6px; }
  .dir { display: flex; align-items: center; gap: 8px; width: 100%; text-align: left; border: none; background: none; padding: 8px 10px; border-radius: 8px; font-size: 14px; cursor: pointer; color: #0f172a; }
  .dir:hover { background: #f1f5f9; }
  .dir .tag { margin-left: auto; font-size: 11px; color: #16a34a; background: #f0fdf4; border: 1px solid #bbf7d0; border-radius: 999px; padding: 1px 8px; }
  .modal-foot { padding: 12px 16px; border-top: 1px solid #e2e8f0; display: flex; gap: 8px; justify-content: flex-end; }
  footer { margin-top: 40px; font-size: 12px; color: #94a3b8; text-align: center; }
  footer a { color: #64748b; }
</style>
</head>
<body>
<div class="container">
  <div class="topbar">
    <div>
      <h1>Security Testing Hub</h1>
      <p class="subtitle" data-i18n="subtitle">Find security holes in your code before someone else does</p>
    </div>
    <div class="langs" id="langs">
      <button data-lang="en">EN</button><button data-lang="ru">RU</button><button data-lang="kk">KK</button>
    </div>
  </div>

  <div class="panel">
    <label class="field" for="path" data-i18n="pathLabel">Project folder</label>
    <div class="row">
      <input type="text" id="path" spellcheck="false" autocomplete="off" />
      <button class="btn" id="browse" data-i18n="browse">Choose folder…</button>
      <button class="btn primary" id="scan" data-i18n="scan">Scan</button>
    </div>
    <p class="privacy" data-i18n="privacy">Everything runs on your computer. Your code is never uploaded anywhere.</p>
    <div class="error hidden" id="error"></div>
  </div>

  <div id="result" class="hidden">
    <div class="score-card" id="score-card">
      <div class="ring" id="ring"><div class="ring-inner"><span class="ring-value" id="ring-value">0</span><span class="ring-max">/ 100</span></div></div>
      <div class="score-meta">
        <p class="score-label" id="score-label"></p>
        <p class="score-sub" id="score-sub"></p>
        <div class="stat-row" id="stats"></div>
      </div>
    </div>
    <div class="warn hidden" id="parse-warn"></div>
    <div class="toolbar">
      <div id="filters" class="row"></div>
      <span class="spacer"></span>
      <button class="btn hidden" id="copy-all" data-i18n="copyAll">Copy one prompt for all findings</button>
      <button class="btn" id="download" data-i18n="download">Download HTML report</button>
    </div>
    <div id="findings"></div>
  </div>

  <footer>
    Security Testing Hub v${escapeAttr(options.version)} ·
    <a href="https://github.com/dam1r-dev/security-testing-hub" target="_blank" rel="noopener noreferrer">GitHub</a> ·
    <span data-i18n="disclaimer">Heuristic static analysis — a helper, not a replacement for security review.</span>
  </footer>
</div>

<div class="modal-backdrop hidden" id="modal">
  <div class="modal" role="dialog" aria-modal="true">
    <div class="modal-head">
      <div class="roots" id="roots"></div>
      <div class="modal-path" id="modal-path"></div>
    </div>
    <div class="modal-list" id="modal-list"></div>
    <div class="modal-foot">
      <button class="btn" id="modal-up" data-i18n="up">Up</button>
      <button class="btn" id="modal-close" data-i18n="close">Close</button>
      <button class="btn primary" id="modal-select" data-i18n="selectFolder">Select this folder</button>
    </div>
  </div>
</div>

<script nonce="${escapeAttr(options.nonce)}">
(function () {
  var TOKEN = document.querySelector('meta[name="token"]').content;
  var INITIAL = document.querySelector('meta[name="initial-path"]');
  var SEVERITIES = ['critical', 'high', 'medium', 'low'];
  var SEVERITY_COLOR = { critical: '#7f1d1d', high: '#dc2626', medium: '#ca8a04', low: '#6b7280' };
  var SCORE_COLOR = {
    green: { main: '#16a34a', bg: '#f0fdf4' },
    yellow: { main: '#ca8a04', bg: '#fefce8' },
    red: { main: '#dc2626', bg: '#fef2f2' }
  };

  var I18N = {
    en: {
      copyFix: 'Copy prompt for my AI assistant', copyAll: 'Copy one prompt for all findings', copied: 'Copied!',
      suppressed: 'Hidden by security-hub-ignore comments: {n}.',
      subtitle: 'Find security holes in your code before someone else does',
      pathLabel: 'Project folder', browse: 'Choose folder\\u2026', scan: 'Scan', scanning: 'Scanning\\u2026',
      privacy: 'Everything runs on your computer. Your code is never uploaded anywhere.',
      download: 'Download HTML report', up: 'Up', close: 'Close', selectFolder: 'Select this folder',
      home: 'Home', all: 'All', critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low',
      Good: 'Good', 'Needs attention': 'Needs attention', 'At risk': 'At risk',
      summary: '{n} finding(s) in {f} scanned file(s), {ms} ms.',
      noFindings: 'No findings \\u2014 nice work. Remember this is a heuristic scanner, not a guarantee.',
      parseWarn: '{n} file(s) could not be fully parsed, so results for them may be incomplete.',
      confidence: 'confidence', emptyFolder: 'No sub-folders here', project: 'project',
      enterPath: 'Enter a folder path first.',
      disclaimer: 'Heuristic static analysis \\u2014 a helper, not a replacement for security review.'
    },
    ru: {
      copyFix: '\\u0421\\u043a\\u043e\\u043f\\u0438\\u0440\\u043e\\u0432\\u0430\\u0442\\u044c \\u043f\\u0440\\u043e\\u043c\\u043f\\u0442 \\u0434\\u043b\\u044f \\u0418\\u0418-\\u0430\\u0441\\u0441\\u0438\\u0441\\u0442\\u0435\\u043d\\u0442\\u0430', copyAll: '\\u0421\\u043a\\u043e\\u043f\\u0438\\u0440\\u043e\\u0432\\u0430\\u0442\\u044c \\u043e\\u0434\\u0438\\u043d \\u043f\\u0440\\u043e\\u043c\\u043f\\u0442 \\u043d\\u0430 \\u0432\\u0441\\u0435 \\u043d\\u0430\\u0445\\u043e\\u0434\\u043a\\u0438', copied: '\\u0421\\u043a\\u043e\\u043f\\u0438\\u0440\\u043e\\u0432\\u0430\\u043d\\u043e!',
      suppressed: '\\u0421\\u043a\\u0440\\u044b\\u0442\\u043e \\u043a\\u043e\\u043c\\u043c\\u0435\\u043d\\u0442\\u0430\\u0440\\u0438\\u044f\\u043c\\u0438 security-hub-ignore: {n}.',
      subtitle: '\\u041d\\u0430\\u0439\\u0434\\u0438\\u0442\\u0435 \\u0443\\u044f\\u0437\\u0432\\u0438\\u043c\\u043e\\u0441\\u0442\\u0438 \\u0432 \\u0441\\u0432\\u043e\\u0451\\u043c \\u043a\\u043e\\u0434\\u0435 \\u0440\\u0430\\u043d\\u044c\\u0448\\u0435, \\u0447\\u0435\\u043c \\u044d\\u0442\\u043e \\u0441\\u0434\\u0435\\u043b\\u0430\\u0435\\u0442 \\u043a\\u0442\\u043e-\\u0442\\u043e \\u0434\\u0440\\u0443\\u0433\\u043e\\u0439',
      pathLabel: '\\u041f\\u0430\\u043f\\u043a\\u0430 \\u043f\\u0440\\u043e\\u0435\\u043a\\u0442\\u0430', browse: '\\u0412\\u044b\\u0431\\u0440\\u0430\\u0442\\u044c \\u043f\\u0430\\u043f\\u043a\\u0443\\u2026', scan: '\\u0421\\u043a\\u0430\\u043d\\u0438\\u0440\\u043e\\u0432\\u0430\\u0442\\u044c', scanning: '\\u0421\\u043a\\u0430\\u043d\\u0438\\u0440\\u0443\\u044e\\u2026',
      privacy: '\\u0412\\u0441\\u0451 \\u0440\\u0430\\u0431\\u043e\\u0442\\u0430\\u0435\\u0442 \\u043d\\u0430 \\u0432\\u0430\\u0448\\u0435\\u043c \\u043a\\u043e\\u043c\\u043f\\u044c\\u044e\\u0442\\u0435\\u0440\\u0435. \\u041a\\u043e\\u0434 \\u043d\\u0438\\u043a\\u0443\\u0434\\u0430 \\u043d\\u0435 \\u043e\\u0442\\u043f\\u0440\\u0430\\u0432\\u043b\\u044f\\u0435\\u0442\\u0441\\u044f.',
      download: '\\u0421\\u043a\\u0430\\u0447\\u0430\\u0442\\u044c HTML-\\u043e\\u0442\\u0447\\u0451\\u0442', up: '\\u0412\\u0432\\u0435\\u0440\\u0445', close: '\\u0417\\u0430\\u043a\\u0440\\u044b\\u0442\\u044c', selectFolder: '\\u0412\\u044b\\u0431\\u0440\\u0430\\u0442\\u044c \\u044d\\u0442\\u0443 \\u043f\\u0430\\u043f\\u043a\\u0443',
      home: '\\u0414\\u043e\\u043c\\u0430\\u0448\\u043d\\u044f\\u044f', all: '\\u0412\\u0441\\u0435', critical: '\\u041a\\u0440\\u0438\\u0442\\u0438\\u0447\\u0435\\u0441\\u043a\\u0438\\u0435', high: '\\u0412\\u044b\\u0441\\u043e\\u043a\\u0438\\u0435', medium: '\\u0421\\u0440\\u0435\\u0434\\u043d\\u0438\\u0435', low: '\\u041d\\u0438\\u0437\\u043a\\u0438\\u0435',
      Good: '\\u0425\\u043e\\u0440\\u043e\\u0448\\u043e', 'Needs attention': '\\u0422\\u0440\\u0435\\u0431\\u0443\\u0435\\u0442 \\u0432\\u043d\\u0438\\u043c\\u0430\\u043d\\u0438\\u044f', 'At risk': '\\u0415\\u0441\\u0442\\u044c \\u0440\\u0438\\u0441\\u043a',
      summary: '\\u041d\\u0430\\u0445\\u043e\\u0434\\u043e\\u043a: {n}, \\u0444\\u0430\\u0439\\u043b\\u043e\\u0432 \\u043f\\u0440\\u043e\\u0432\\u0435\\u0440\\u0435\\u043d\\u043e: {f}, {ms} \\u043c\\u0441.',
      noFindings: '\\u041d\\u0438\\u0447\\u0435\\u0433\\u043e \\u043d\\u0435 \\u043d\\u0430\\u0439\\u0434\\u0435\\u043d\\u043e \\u2014 \\u0445\\u043e\\u0440\\u043e\\u0448\\u0430\\u044f \\u0440\\u0430\\u0431\\u043e\\u0442\\u0430. \\u041d\\u043e \\u044d\\u0442\\u043e \\u044d\\u0432\\u0440\\u0438\\u0441\\u0442\\u0438\\u0447\\u0435\\u0441\\u043a\\u0438\\u0439 \\u0441\\u043a\\u0430\\u043d\\u0435\\u0440, \\u0430 \\u043d\\u0435 \\u0433\\u0430\\u0440\\u0430\\u043d\\u0442\\u0438\\u044f.',
      parseWarn: '\\u0424\\u0430\\u0439\\u043b\\u043e\\u0432, \\u043a\\u043e\\u0442\\u043e\\u0440\\u044b\\u0435 \\u043d\\u0435 \\u0443\\u0434\\u0430\\u043b\\u043e\\u0441\\u044c \\u0440\\u0430\\u0437\\u043e\\u0431\\u0440\\u0430\\u0442\\u044c \\u043f\\u043e\\u043b\\u043d\\u043e\\u0441\\u0442\\u044c\\u044e: {n}. \\u0414\\u043b\\u044f \\u043d\\u0438\\u0445 \\u0440\\u0435\\u0437\\u0443\\u043b\\u044c\\u0442\\u0430\\u0442 \\u043c\\u043e\\u0436\\u0435\\u0442 \\u0431\\u044b\\u0442\\u044c \\u043d\\u0435\\u043f\\u043e\\u043b\\u043d\\u044b\\u043c.',
      confidence: '\\u0443\\u0432\\u0435\\u0440\\u0435\\u043d\\u043d\\u043e\\u0441\\u0442\\u044c', emptyFolder: '\\u0412\\u043b\\u043e\\u0436\\u0435\\u043d\\u043d\\u044b\\u0445 \\u043f\\u0430\\u043f\\u043e\\u043a \\u043d\\u0435\\u0442', project: '\\u043f\\u0440\\u043e\\u0435\\u043a\\u0442',
      enterPath: '\\u0421\\u043d\\u0430\\u0447\\u0430\\u043b\\u0430 \\u0443\\u043a\\u0430\\u0436\\u0438\\u0442\\u0435 \\u043f\\u0443\\u0442\\u044c \\u043a \\u043f\\u0430\\u043f\\u043a\\u0435.',
      disclaimer: '\\u042d\\u0432\\u0440\\u0438\\u0441\\u0442\\u0438\\u0447\\u0435\\u0441\\u043a\\u0438\\u0439 \\u0441\\u0442\\u0430\\u0442\\u0438\\u0447\\u0435\\u0441\\u043a\\u0438\\u0439 \\u0430\\u043d\\u0430\\u043b\\u0438\\u0437 \\u2014 \\u043f\\u043e\\u043c\\u043e\\u0449\\u043d\\u0438\\u043a, \\u0430 \\u043d\\u0435 \\u0437\\u0430\\u043c\\u0435\\u043d\\u0430 \\u0430\\u0443\\u0434\\u0438\\u0442\\u0443 \\u0431\\u0435\\u0437\\u043e\\u043f\\u0430\\u0441\\u043d\\u043e\\u0441\\u0442\\u0438.'
    },
    kk: {
      copyFix: '\\u0416\\u0418-\\u043a\\u04e9\\u043c\\u0435\\u043a\\u0448\\u0456 \\u04af\\u0448\\u0456\\u043d \\u043f\\u0440\\u043e\\u043c\\u043f\\u0442\\u0442\\u044b \\u043a\\u04e9\\u0448\\u0456\\u0440\\u0443', copyAll: '\\u0411\\u0430\\u0440\\u043b\\u044b\\u049b \\u0442\\u0430\\u0431\\u044b\\u043b\\u044b\\u043c\\u0434\\u0430\\u0440\\u0493\\u0430 \\u0431\\u0456\\u0440 \\u043f\\u0440\\u043e\\u043c\\u043f\\u0442 \\u043a\\u04e9\\u0448\\u0456\\u0440\\u0443', copied: '\\u041a\\u04e9\\u0448\\u0456\\u0440\\u0456\\u043b\\u0434\\u0456!',
      suppressed: 'security-hub-ignore \\u0442\\u04af\\u0441\\u0456\\u043d\\u0456\\u043a\\u0442\\u0435\\u043c\\u0435\\u043b\\u0435\\u0440\\u0456\\u043c\\u0435\\u043d \\u0436\\u0430\\u0441\\u044b\\u0440\\u044b\\u043b\\u0493\\u0430\\u043d: {n}.',
      subtitle: '\\u041a\\u043e\\u0434\\u044b\\u04a3\\u044b\\u0437\\u0434\\u0430\\u0493\\u044b \\u043e\\u0441\\u0430\\u043b\\u0434\\u044b\\u049b\\u0442\\u0430\\u0440\\u0434\\u044b \\u0431\\u0430\\u0441\\u049b\\u0430\\u043b\\u0430\\u0440 \\u0442\\u0430\\u0431\\u0443\\u0434\\u0430\\u043d \\u0431\\u04b1\\u0440\\u044b\\u043d \\u0442\\u0430\\u0431\\u044b\\u04a3\\u044b\\u0437',
      pathLabel: '\\u0416\\u043e\\u0431\\u0430 \\u049b\\u0430\\u043b\\u0442\\u0430\\u0441\\u044b', browse: '\\u049a\\u0430\\u043b\\u0442\\u0430\\u043d\\u044b \\u0442\\u0430\\u04a3\\u0434\\u0430\\u0443\\u2026', scan: '\\u0421\\u043a\\u0430\\u043d\\u0435\\u0440\\u043b\\u0435\\u0443', scanning: '\\u0421\\u043a\\u0430\\u043d\\u0435\\u0440\\u043b\\u0435\\u0443\\u0434\\u0435\\u2026',
      privacy: '\\u0411\\u0430\\u0440\\u043b\\u044b\\u0493\\u044b \\u0441\\u0456\\u0437\\u0434\\u0456\\u04a3 \\u043a\\u043e\\u043c\\u043f\\u044c\\u044e\\u0442\\u0435\\u0440\\u0456\\u04a3\\u0456\\u0437\\u0434\\u0435 \\u0436\\u04b1\\u043c\\u044b\\u0441 \\u0456\\u0441\\u0442\\u0435\\u0439\\u0434\\u0456. \\u041a\\u043e\\u0434 \\u0438\\u043d\\u0442\\u0435\\u0440\\u043d\\u0435\\u0442\\u043a\\u0435 \\u0436\\u0456\\u0431\\u0435\\u0440\\u0456\\u043b\\u043c\\u0435\\u0439\\u0434\\u0456.',
      download: 'HTML \\u0435\\u0441\\u0435\\u043f\\u0442\\u0456 \\u0436\\u04af\\u043a\\u0442\\u0435\\u0443', up: '\\u0416\\u043e\\u0493\\u0430\\u0440\\u044b', close: '\\u0416\\u0430\\u0431\\u0443', selectFolder: '\\u041e\\u0441\\u044b \\u049b\\u0430\\u043b\\u0442\\u0430\\u043d\\u044b \\u0442\\u0430\\u04a3\\u0434\\u0430\\u0443',
      home: '\\u04ae\\u0439 \\u049b\\u0430\\u043b\\u0442\\u0430\\u0441\\u044b', all: '\\u0411\\u0430\\u0440\\u043b\\u044b\\u0493\\u044b', critical: '\\u041a\\u0440\\u0438\\u0442\\u0438\\u043a\\u0430\\u043b\\u044b\\u049b', high: '\\u0416\\u043e\\u0493\\u0430\\u0440\\u044b', medium: '\\u041e\\u0440\\u0442\\u0430\\u0448\\u0430', low: '\\u0422\\u04e9\\u043c\\u0435\\u043d',
      Good: '\\u0416\\u0430\\u049b\\u0441\\u044b', 'Needs attention': '\\u041d\\u0430\\u0437\\u0430\\u0440 \\u0430\\u0443\\u0434\\u0430\\u0440\\u0443 \\u043a\\u0435\\u0440\\u0435\\u043a', 'At risk': '\\u049a\\u0430\\u0443\\u0456\\u043f \\u0431\\u0430\\u0440',
      summary: '\\u0422\\u0430\\u0431\\u044b\\u043b\\u044b\\u043c\\u0434\\u0430\\u0440: {n}, \\u0442\\u0435\\u043a\\u0441\\u0435\\u0440\\u0456\\u043b\\u0433\\u0435\\u043d \\u0444\\u0430\\u0439\\u043b\\u0434\\u0430\\u0440: {f}, {ms} \\u043c\\u0441.',
      noFindings: '\\u0415\\u0448\\u0442\\u0435\\u04a3\\u0435 \\u0442\\u0430\\u0431\\u044b\\u043b\\u043c\\u0430\\u0434\\u044b \\u2014 \\u0436\\u0430\\u049b\\u0441\\u044b \\u0436\\u04b1\\u043c\\u044b\\u0441. \\u0411\\u0456\\u0440\\u0430\\u049b \\u0431\\u04b1\\u043b \\u044d\\u0432\\u0440\\u0438\\u0441\\u0442\\u0438\\u043a\\u0430\\u043b\\u044b\\u049b \\u0441\\u043a\\u0430\\u043d\\u0435\\u0440, \\u043a\\u0435\\u043f\\u0456\\u043b\\u0434\\u0456\\u043a \\u0435\\u043c\\u0435\\u0441.',
      parseWarn: '\\u0422\\u043e\\u043b\\u044b\\u049b \\u0442\\u0430\\u043b\\u0434\\u0430\\u043d\\u0431\\u0430\\u0493\\u0430\\u043d \\u0444\\u0430\\u0439\\u043b\\u0434\\u0430\\u0440: {n}. \\u0415\\u0441\\u0435\\u043f \\u0442\\u043e\\u043b\\u044b\\u049b \\u0431\\u043e\\u043b\\u043c\\u0430\\u0443\\u044b \\u043c\\u04af\\u043c\\u043a\\u0456\\u043d.',
      confidence: '\\u0441\\u0435\\u043d\\u0456\\u043c\\u0434\\u0456\\u043b\\u0456\\u043a', emptyFolder: '\\u0406\\u0448\\u043a\\u0456 \\u049b\\u0430\\u043b\\u0442\\u0430\\u043b\\u0430\\u0440 \\u0436\\u043e\\u049b', project: '\\u0436\\u043e\\u0431\\u0430',
      enterPath: '\\u0410\\u043b\\u0434\\u044b\\u043c\\u0435\\u043d \\u049b\\u0430\\u043b\\u0442\\u0430 \\u0436\\u043e\\u043b\\u044b\\u043d \\u043a\\u04e9\\u0440\\u0441\\u0435\\u0442\\u0456\\u04a3\\u0456\\u0437.',
      disclaimer: '\\u042d\\u0432\\u0440\\u0438\\u0441\\u0442\\u0438\\u043a\\u0430\\u043b\\u044b\\u049b \\u0441\\u0442\\u0430\\u0442\\u0438\\u043a\\u0430\\u043b\\u044b\\u049b \\u0442\\u0430\\u043b\\u0434\\u0430\\u0443 \\u2014 \\u043a\\u04e9\\u043c\\u0435\\u043a\\u0448\\u0456, \\u049b\\u0430\\u0443\\u0456\\u043f\\u0441\\u0456\\u0437\\u0434\\u0456\\u043a \\u0430\\u0443\\u0434\\u0438\\u0442\\u0456\\u043d\\u0456\\u04a3 \\u043e\\u0440\\u043d\\u044b\\u043d \\u0431\\u0430\\u0441\\u043f\\u0430\\u0439\\u0434\\u044b.'
    }
  };

  function store(key, value) {
    try { if (value === undefined) return localStorage.getItem(key); localStorage.setItem(key, value); } catch (e) { return null; }
    return null;
  }

  var lang = store('sh-lang');
  if (!I18N[lang]) lang = (navigator.language || 'en').slice(0, 2);
  if (!I18N[lang]) lang = 'en';

  function t(key) { return (I18N[lang] && I18N[lang][key]) || I18N.en[key] || key; }
  function fmt(key, vars) {
    return t(key).replace(/\\{(\\w+)\\}/g, function (m, name) { return String(vars[name]); });
  }
  function el(tag, cls, text) {
    var node = document.createElement(tag);
    if (cls) node.className = cls;
    if (text !== undefined) node.textContent = text;
    return node;
  }
  function $(id) { return document.getElementById(id); }

  function api(url, body) {
    var init = { headers: { 'x-security-hub-token': TOKEN } };
    if (body) {
      init.method = 'POST';
      init.headers['content-type'] = 'application/json';
      init.body = JSON.stringify(body);
    }
    return fetch(url, init).then(function (res) {
      return res.json().then(function (json) {
        if (!res.ok) throw new Error(json.error || 'HTTP ' + res.status);
        return json;
      });
    });
  }

  var lastResult = null;
  var activeFilter = 'all';
  var busy = false;

  function applyLang() {
    document.documentElement.lang = lang;
    document.querySelectorAll('[data-i18n]').forEach(function (node) {
      node.textContent = t(node.getAttribute('data-i18n'));
    });
    document.querySelectorAll('#langs button').forEach(function (b) {
      b.classList.toggle('active', b.getAttribute('data-lang') === lang);
    });
    if (busy) $('scan').textContent = t('scanning');
    if (lastResult) renderResult();
  }

  function showError(message) {
    var box = $('error');
    box.textContent = message || '';
    box.classList.toggle('hidden', !message);
  }

  function relativePath(file, target) {
    var norm = function (p) { return p.replace(/\\\\/g, '/'); };
    var f = norm(file), base = norm(target).replace(/\\/$/, '');
    return f.indexOf(base + '/') === 0 ? f.slice(base.length + 1) : file;
  }

  function renderResult() {
    var data = lastResult;
    var score = data.score;
    var colors = SCORE_COLOR[score.color];
    $('result').classList.remove('hidden');

    var card = $('score-card');
    card.style.background = colors.bg;
    card.style.borderColor = colors.main + '55';
    var ring = $('ring');
    ring.style.setProperty('--v', String(score.value));
    ring.style.setProperty('--c', colors.main);
    $('ring-value').textContent = String(score.value);
    $('ring-value').style.color = colors.main;
    var label = $('score-label');
    label.textContent = t(score.label);
    label.style.color = colors.main;
    var sub = fmt('summary', { n: score.totalFindings, f: data.summary.filesScanned, ms: data.summary.durationMs });
    if (data.summary.suppressedCount) sub += ' ' + fmt('suppressed', { n: data.summary.suppressedCount });
    $('score-sub').textContent = sub;

    var stats = $('stats');
    stats.textContent = '';
    SEVERITIES.forEach(function (sev) {
      var box = el('div', 'stat');
      box.style.borderColor = SEVERITY_COLOR[sev] + '55';
      var n = el('span', 'n', String(score.bySeverity[sev]));
      n.style.color = SEVERITY_COLOR[sev];
      box.appendChild(n);
      box.appendChild(el('span', 'l', t(sev)));
      stats.appendChild(box);
    });

    var parseIssues = data.results.filter(function (r) { return r.parseError; });
    var warn = $('parse-warn');
    warn.classList.toggle('hidden', parseIssues.length === 0);
    warn.textContent = parseIssues.length ? fmt('parseWarn', { n: parseIssues.length }) : '';

    var filters = $('filters');
    filters.textContent = '';
    ['all'].concat(SEVERITIES).forEach(function (f) {
      var count = f === 'all' ? score.totalFindings : score.bySeverity[f];
      var chip = el('button', 'chip' + (f === activeFilter ? ' active' : ''), t(f) + ' (' + count + ')');
      chip.addEventListener('click', function () { activeFilter = f; renderResult(); });
      filters.appendChild(chip);
    });

    var copyAll = $('copy-all');
    copyAll.classList.toggle('hidden', !data.allPrompt);
    copyAll.textContent = t('copyAll');
    copyAll.onclick = function () { copyText(data.allPrompt, copyAll, 'copyAll'); };

    var list = $('findings');
    list.textContent = '';
    var shown = 0;
    var all = [];
    data.results.forEach(function (r) { r.findings.forEach(function (f) { all.push(f); }); });
    // Most severe first; the sort is stable, so order within a severity is the scan order.
    all.sort(function (a, b) { return SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity); });
    all.forEach(function (f) {
      if (activeFilter !== 'all' && f.severity !== activeFilter) return;
      shown++;
      var item = el('article', 'finding');
      var head = el('div', 'finding-head');
      var badge = el('span', 'badge', t(f.severity));
      badge.style.background = SEVERITY_COLOR[f.severity];
      head.appendChild(badge);
      head.appendChild(el('span', 'rule-id', f.ruleId));
      head.appendChild(el('span', 'confidence', t('confidence') + ': ' + f.confidence));
      item.appendChild(head);
      item.appendChild(el('p', 'message', f.message));
      item.appendChild(el('div', 'location', relativePath(f.location.file, data.target) + ':' + f.location.startLine + ':' + f.location.startColumn));
      var pre = el('pre', 'snippet');
      pre.appendChild(el('code', '', f.sinkSnippet));
      item.appendChild(pre);
      var copy = el('button', 'btn small', t('copyFix'));
      copy.addEventListener('click', function () { copyText(f.fixPrompt, copy, 'copyFix'); });
      item.appendChild(copy);
      list.appendChild(item);
    });
    if (shown === 0) list.appendChild(el('p', 'empty-state', t('noFindings')));
  }

  function copyText(text, button, label) {
    var done = function () {
      button.textContent = t('copied');
      setTimeout(function () { button.textContent = t(label); }, 1500);
    };
    var fallback = function () {
      var area = document.createElement('textarea');
      area.value = text; area.style.position = 'fixed'; area.style.opacity = '0';
      document.body.appendChild(area); area.select();
      try { document.execCommand('copy'); done(); } catch (e) { /* nothing more to try */ }
      document.body.removeChild(area);
    };
    if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(text).then(done, fallback);
    else fallback();
  }

  function runScan() {
    var target = $('path').value.trim();
    if (!target) { showError(t('enterPath')); return; }
    showError('');
    busy = true;
    $('scan').disabled = true;
    $('scan').textContent = t('scanning');
    api('/api/scan', { path: target }).then(function (data) {
      lastResult = data;
      activeFilter = 'all';
      store('sh-last-path', target);
      renderResult();
      $('result').scrollIntoView({ behavior: 'smooth', block: 'start' });
    }).catch(function (err) {
      showError(err.message);
    }).then(function () {
      busy = false;
      $('scan').disabled = false;
      $('scan').textContent = t('scan');
    });
  }

  function downloadReport() {
    if (!lastResult) return;
    var blob = new Blob([lastResult.html], { type: 'text/html' });
    var link = document.createElement('a');
    link.href = URL.createObjectURL(blob);
    link.download = 'security-report.html';
    document.body.appendChild(link);
    link.click();
    link.remove();
    setTimeout(function () { URL.revokeObjectURL(link.href); }, 1000);
  }

  // --- folder browser -------------------------------------------------------
  var browseState = { dir: '', parent: null };

  function loadDir(dir) {
    api('/api/browse' + (dir ? '?dir=' + encodeURIComponent(dir) : '')).then(function (data) {
      browseState.dir = data.dir;
      browseState.parent = data.parent;
      $('modal-path').textContent = data.dir;
      $('modal-up').disabled = !data.parent;

      var roots = $('roots');
      roots.textContent = '';
      data.roots.forEach(function (root) {
        var b = el('button', 'btn', root.name === 'Home' ? t('home') : root.name);
        b.addEventListener('click', function () { loadDir(root.path); });
        roots.appendChild(b);
      });

      var list = $('modal-list');
      list.textContent = '';
      if (data.entries.length === 0) list.appendChild(el('p', 'privacy', t('emptyFolder')));
      data.entries.forEach(function (entry) {
        var row = el('button', 'dir');
        row.appendChild(el('span', '', '\\uD83D\\uDCC1'));
        row.appendChild(el('span', '', entry.name));
        if (entry.isProject) row.appendChild(el('span', 'tag', t('project')));
        row.addEventListener('click', function () { loadDir(entry.path); });
        list.appendChild(row);
      });
    }).catch(function (err) {
      $('modal-list').textContent = '';
      $('modal-list').appendChild(el('p', 'error', err.message));
    });
  }

  function openBrowser() {
    $('modal').classList.remove('hidden');
    loadDir($('path').value.trim());
  }
  function closeBrowser() { $('modal').classList.add('hidden'); }

  // --- wiring ---------------------------------------------------------------
  $('scan').addEventListener('click', runScan);
  $('path').addEventListener('keydown', function (e) { if (e.key === 'Enter') runScan(); });
  $('browse').addEventListener('click', openBrowser);
  $('download').addEventListener('click', downloadReport);
  $('modal-close').addEventListener('click', closeBrowser);
  $('modal-up').addEventListener('click', function () { if (browseState.parent) loadDir(browseState.parent); });
  $('modal-select').addEventListener('click', function () { $('path').value = browseState.dir; closeBrowser(); });
  $('modal').addEventListener('click', function (e) { if (e.target === $('modal')) closeBrowser(); });
  document.addEventListener('keydown', function (e) { if (e.key === 'Escape') closeBrowser(); });
  document.querySelectorAll('#langs button').forEach(function (b) {
    b.addEventListener('click', function () {
      lang = b.getAttribute('data-lang');
      store('sh-lang', lang);
      applyLang();
    });
  });

  var explicit = INITIAL.getAttribute('data-explicit') === '1';
  $('path').value = (!explicit && store('sh-last-path')) || INITIAL.content;
  applyLang();
})();
</script>
</body>
</html>`;
}
