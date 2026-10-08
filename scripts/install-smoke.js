"use strict";
// Install smoke test: what a new user does, on a clean folder.
//   1. pack both packages (exactly what `npm publish` would upload),
//   2. install the tarballs into an empty project (pulls tree-sitter and its native binding from the registry),
//   3. run the CLI: --version, a scan of the example app, the web interface.
// Run from the repository root after `npm run build`:  node scripts/install-smoke.js
// The native parser is the likeliest thing to break for a new user (Windows, macOS, a new Node), so CI runs this
// on every OS/Node combination instead of trusting that "it works on my machine".

const { execFileSync, spawn } = require("child_process");
const fs = require("fs");
const http = require("http");
const os = require("os");
const path = require("path");

const root = path.resolve(__dirname, "..");
const npm = process.platform === "win32" ? "npm.cmd" : "npm";
const work = fs.mkdtempSync(path.join(os.tmpdir(), "sh-smoke-"));
let failed = false;

function run(command, args, options = {}) {
  // npm.cmd on Windows must go through a shell; everything else is a plain execFile.
  return execFileSync(command, args, { encoding: "utf8", shell: command === npm && process.platform === "win32", ...options });
}

function check(label, condition, detail = "") {
  console.log(`${condition ? "ok  " : "FAIL"} ${label}${condition || !detail ? "" : `: ${detail}`}`);
  if (!condition) failed = true;
}

function pack(packageDir) {
  const out = run(npm, ["pack", "--silent", "--pack-destination", work], { cwd: path.join(root, packageDir) });
  return path.join(work, out.trim().split(/\r?\n/).pop());
}

function waitForUrl(child) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("the web interface did not print its URL within 30 s")), 30000);
    let buffer = "";
    child.stdout.on("data", (chunk) => {
      buffer += chunk;
      const match = /http:\/\/127\.0\.0\.1:\d+\//.exec(buffer);
      if (match) {
        clearTimeout(timer);
        resolve(match[0]);
      }
    });
    child.on("exit", (code) => reject(new Error(`the web interface exited early (code ${code})`)));
  });
}

function get(url, headers = {}) {
  return new Promise((resolve, reject) => {
    http.get(url, { headers }, (res) => {
      res.resume();
      res.on("end", () => resolve(res.statusCode));
    }).on("error", reject);
  });
}

async function main() {
  const version = JSON.parse(fs.readFileSync(path.join(root, "packages/cli/package.json"), "utf8")).version;
  console.log(`node ${process.version} on ${process.platform}/${process.arch}, packages ${version}`);

  const tarballs = [pack("packages/scanner"), pack("packages/cli")];
  const project = path.join(work, "project");
  fs.mkdirSync(project);
  run(npm, ["init", "-y"], { cwd: project });
  run(npm, ["install", "--no-audit", "--no-fund", ...tarballs], { cwd: project, stdio: "pipe" });
  check("tarballs install into an empty project", fs.existsSync(path.join(project, "node_modules", "security-hub")));

  const bin = path.join(project, "node_modules", "security-hub", "bin", "security-hub.js");
  check("--version matches the package", run(process.execPath, [bin, "--version"]).trim() === version);

  const example = path.join(root, "examples", "vulnerable-express-app");
  const out = path.join(work, "result.json");
  run(process.execPath, [bin, "scan", example, "--format", "json", "--out", out], { stdio: "pipe" });
  const result = JSON.parse(fs.readFileSync(out, "utf8"));
  const rules = new Set(result.results.flatMap((r) => r.findings.map((f) => f.ruleId)));
  check("scan runs the native parser and finds the planted bugs", result.findingsCount >= 20, `findings: ${result.findingsCount}`);
  check("scan reports every rule family", ["sql-injection", "xss", "hardcoded-secret", "idor"].every((r) => rules.has(r)));
  const reports = result.results.find((r) => /reports\.js$/.test(r.file));
  check("scan follows data across files", Boolean(reports && reports.findings.some((f) => f.ruleId === "sql-injection")));
  check("scan prints no secret in full", !JSON.stringify(result).includes("Sup3rS3cret"));

  const ui = spawn(process.execPath, [bin, "ui", "--no-open", "--port", "0"], { cwd: project });
  try {
    const url = await waitForUrl(ui);
    check("web interface serves its page", (await get(url)) === 200);
    check("web interface refuses API calls without its token", (await get(`${url}api/browse`)) === 403);
  } finally {
    ui.kill();
  }
}

main()
  .catch((err) => {
    console.log(`FAIL ${err.message}`);
    failed = true;
  })
  .finally(() => {
    try {
      fs.rmSync(work, { recursive: true, force: true });
    } catch {
      // temp folder cleanup is best-effort (Windows may still hold a file open)
    }
    process.exit(failed ? 1 : 0);
  });
