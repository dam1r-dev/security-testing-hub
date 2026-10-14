#!/usr/bin/env node
// The site's Content-Security-Policy allows exactly one inline script: the one in site/index.html, by its SHA-256 hash
// (a meta tag cannot carry a nonce). Any other script, injected or edited in, will not run.
//
//   node scripts/update-site-csp.js          rewrite the hash in site/index.html after editing the script
//   node scripts/update-site-csp.js --check  exit 1 when the hash is out of date (a test does this)
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const file = path.resolve(__dirname, "..", "site", "index.html");

function compute(html) {
  const scripts = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)];
  if (scripts.length !== 1) throw new Error(`site/index.html must have exactly one inline <script> (found ${scripts.length})`);
  const hash = crypto.createHash("sha256").update(scripts[0][1], "utf8").digest("base64");
  return `'sha256-${hash}'`;
}

const original = fs.readFileSync(file, "utf8");
const normalized = original.replace(/\r\n/g, "\n"); // git on Windows may check the file out with CRLF: hash the LF form
const expected = compute(normalized);
const pattern = /script-src [^;]*;/;
const current = (pattern.exec(normalized) || [""])[0];

if (process.argv.includes("--check")) {
  if (current !== `script-src ${expected};`) {
    console.error(`site/index.html: the CSP script hash is out of date (expected ${expected}): run \`node scripts/update-site-csp.js\``);
    process.exit(1);
  }
} else {
  const updated = normalized.replace(pattern, `script-src ${expected};`);
  fs.writeFileSync(file, original.includes("\r\n") ? updated.replace(/\n/g, "\r\n") : updated);
  console.log(`site/index.html: script-src ${expected}`);
}
