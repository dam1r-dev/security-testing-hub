#!/usr/bin/env node
// Builds docs/demo.svg (also copied to site/assets/demo.svg): an animated terminal that replays a REAL scan of
// examples/vulnerable-express-app with the current scanner. An SVG, not a GIF: it stays sharp, is a few KB, and the
// README and the website show it with a plain <img> (the animation runs inside an image).
//   npm run build && node scripts/build-demo.js
const fs = require("fs");
const path = require("path");

const root = path.resolve(__dirname, "..");
const { scanPath, computeScore, mascotDataUri } = require(path.join(root, "packages", "scanner", "dist", "index.js"));

const target = path.join(root, "examples", "vulnerable-express-app");
const summary = scanPath(target, { config: false });
const score = computeScore(summary);

const SEVERITY_COLOR = { critical: "#ef4444", high: "#f97316", medium: "#eab308", low: "#9ca3af" };
const PICK = ["sql-injection", "command-injection", "hardcoded-secret", "path-traversal", "ssrf", "insecure-cors"];

const all = summary.results.flatMap((r) => r.findings.map((f) => ({ file: path.relative(target, r.file).split(path.sep).join("/"), f })));
const chosen = [];
for (const rule of PICK) {
  const hit = all.find((x) => x.f.ruleId === rule);
  if (hit) chosen.push(hit);
}

const escape = (text) => text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
const clip = (text, max) => (text.length > max ? `${text.slice(0, max - 1)}…` : text);
const firstSentence = (m) => (/^(.*?[.!?])(\s|$)/.exec(m) || [, m])[1];

// Lines of the terminal, each appearing in turn. `at` is the second it appears.
const lines = [{ at: 0.3, parts: [{ t: "$ ", c: "#22c55e" }, { t: "npx security-hub scan .", c: "#e5e7eb" }] }];
let at = 1.4;
for (const { file, f } of chosen) {
  lines.push({ at, parts: [{ t: ` ${f.severity.toUpperCase()} `, c: "#111827", bg: SEVERITY_COLOR[f.severity] }, { t: `  ${f.ruleId}  `, c: "#f9fafb", bold: true }, { t: `${file}:${f.location.startLine}`, c: "#9ca3af" }] });
  lines.push({ at: at + 0.25, parts: [{ t: `  ${clip(firstSentence(f.message), 92)}`, c: "#d1d5db" }] });
  at += 0.9;
}
lines.push({ at: at + 0.2, parts: [{ t: `Scanned ${summary.filesScanned} files — ${summary.findingsCount} findings.`, c: "#e5e7eb", bold: true }] });
const scoreColor = { green: "#16a34a", yellow: "#ca8a04", red: "#dc2626" }[score.color];
lines.push({ at: at + 0.7, parts: [{ t: ` ${score.value}/100 — ${score.label} `, c: "#ffffff", bg: scoreColor, bold: true }, { t: `   critical ${score.bySeverity.critical} · high ${score.bySeverity.high} · medium ${score.bySeverity.medium} · low ${score.bySeverity.low}`, c: "#9ca3af" }] });
const END = at + 0.7;
const LOOP = END + 5; // seconds: everything stays visible for 5 s, then it starts over

const LINE_HEIGHT = 24;
const WIDTH = 880;
const HEIGHT = 64 + lines.length * LINE_HEIGHT + 24;
const CHAR = 8.45; // monospace 14 px

const css = [];
const body = lines
  .map((line, i) => {
    const y = 56 + i * LINE_HEIGHT;
    const start = ((line.at / LOOP) * 100).toFixed(2);
    css.push(`.l${i}{opacity:0;animation:a${i} ${LOOP}s linear infinite}@keyframes a${i}{0%,${start}%{opacity:0}${(Number(start) + 0.6).toFixed(2)}%,96%{opacity:1}100%{opacity:0}}`);
    let x = 24;
    const spans = line.parts
      .map((p) => {
        const width = p.t.length * CHAR;
        const rect = p.bg ? `<rect x="${x.toFixed(1)}" y="${y - 15}" width="${width.toFixed(1)}" height="20" rx="3" fill="${p.bg}"/>` : "";
        const text = `<text x="${x.toFixed(1)}" y="${y}" fill="${p.c}"${p.bold ? ' font-weight="700"' : ""} xml:space="preserve">${escape(p.t)}</text>`;
        x += width;
        return rect + text;
      })
      .join("");
    return `<g class="l${i}">${spans}</g>`;
  })
  .join("\n");

const svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${WIDTH} ${HEIGHT}" width="${WIDTH}" height="${HEIGHT}" role="img" aria-label="Security Testing Hub scanning a deliberately vulnerable app: ${summary.findingsCount} findings, score ${score.value} out of 100">
<style>text{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,"Liberation Mono",monospace;font-size:14px}${css.join("")}</style>
<rect width="${WIDTH}" height="${HEIGHT}" rx="12" fill="#0b1220"/>
<rect width="${WIDTH}" height="34" rx="12" fill="#111a2e"/><rect y="22" width="${WIDTH}" height="12" fill="#111a2e"/>
<circle cx="22" cy="17" r="6" fill="#ef4444"/><circle cx="42" cy="17" r="6" fill="#eab308"/><circle cx="62" cy="17" r="6" fill="#22c55e"/>
<text x="${WIDTH / 2}" y="22" fill="#94a3b8" text-anchor="middle" style="font-size:12px">security-hub scan examples/vulnerable-express-app</text>
${body}
<image x="${WIDTH - 128}" y="${HEIGHT - 124}" width="104" height="104" href="${mascotDataUri(score.color)}"/>
</svg>
`;

fs.writeFileSync(path.join(root, "docs", "demo.svg"), svg);
fs.writeFileSync(path.join(root, "site", "assets", "demo.svg"), svg);
console.log(`docs/demo.svg: ${(svg.length / 1024).toFixed(0)} KB, ${chosen.length} findings shown of ${summary.findingsCount}, score ${score.value}`);
