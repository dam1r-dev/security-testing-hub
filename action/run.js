"use strict";
// Entry point of the Security Testing Hub GitHub Action (see ../action.yml).
// Plain Node, no dependencies, no build step: the action runs straight from this repository.
//
// Flow: install/load the scanner -> scan the WHOLE project -> narrow the report to the files
// a pull request changed -> annotations + job summary + (optional) sticky PR comment + SARIF
// -> report pass/fail through outputs. Failing the job is left to the last step of action.yml
// so the comment and the SARIF upload still happen when the gate trips.

const fs = require("fs");
const os = require("os");
const path = require("path");
const { execFileSync } = require("child_process");

const VERSION_PATTERN = /^(latest|local|\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)$/;
const SEVERITIES = ["low", "medium", "high", "critical"];
const COMMENT_PAGES = 5;

function parseList(text) {
  return (text || "")
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line !== "" && !line.startsWith("#"));
}

function parseBool(value, fallback) {
  if (value === undefined || value === "") return fallback;
  return /^(true|1|yes)$/i.test(String(value).trim());
}

function parseSeverity(value, name) {
  const normalized = (value || "").trim().toLowerCase();
  if (normalized === "") return undefined;
  if (!SEVERITIES.includes(normalized)) {
    throw new Error(`Input "${name}" must be one of ${SEVERITIES.join(", ")} (got "${value}").`);
  }
  return normalized;
}

function loadScanner(env, deps) {
  const version = (env.INPUT_VERSION || "latest").trim();
  if (!VERSION_PATTERN.test(version)) {
    throw new Error(`Input "version" must be "latest", "local" or an exact version like 0.5.0 (got "${version}").`);
  }
  if (deps.scanner) return deps.scanner;
  if (version === "local") {
    // Used by this repository's own workflow: scan with the freshly built checkout.
    return require(path.join(env.GITHUB_WORKSPACE || process.cwd(), "packages", "scanner"));
  }
  const prefix = fs.mkdtempSync(path.join(env.RUNNER_TEMP || os.tmpdir(), "security-hub-"));
  deps.log(`Installing security-hub-scanner@${version} ...`);
  deps.exec("npm", ["install", "--no-audit", "--no-fund", "--loglevel=error", "--prefix", prefix, `security-hub-scanner@${version}`]);
  return require(path.join(prefix, "node_modules", "security-hub-scanner"));
}

/** Makes `origin/<base>` available with enough history for a merge-base diff. */
function ensureBaseRef(base, deps) {
  const ref = `refs/remotes/origin/${base}`;
  try {
    deps.exec("git", ["rev-parse", "--verify", "--quiet", ref]);
  } catch {
    deps.exec("git", ["fetch", "--no-tags", "origin", `+refs/heads/${base}:${ref}`]);
  }
  try {
    if (deps.exec("git", ["rev-parse", "--is-shallow-repository"]).trim() === "true") {
      deps.exec("git", ["fetch", "--no-tags", "--unshallow", "origin"]);
    }
  } catch (err) {
    deps.log(`::warning::Could not fetch full history (${firstLine(err)}); changed-file detection may be incomplete.`);
  }
  return `origin/${base}`;
}

function firstLine(err) {
  return String((err && err.message) || err).split("\n")[0];
}

function readEvent(env) {
  try {
    return JSON.parse(fs.readFileSync(env.GITHUB_EVENT_PATH, "utf8"));
  } catch {
    return {};
  }
}

function appendFile(file, text) {
  if (file) fs.appendFileSync(file, text);
}

async function api(deps, env, method, url, body) {
  const response = await deps.fetch(url, {
    method,
    headers: {
      authorization: `Bearer ${env.INPUT_GITHUB_TOKEN}`,
      accept: "application/vnd.github+json",
      "content-type": "application/json",
      "x-github-api-version": "2022-11-28",
      "user-agent": "security-testing-hub-action",
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (!response.ok) {
    const error = new Error(`GitHub API ${method} ${url.replace(/^https?:\/\/[^/]+/, "")} -> ${response.status}`);
    error.status = response.status;
    throw error;
  }
  return response.json();
}

/** Creates the comment, or updates the one this action posted earlier (found by its hidden marker). */
async function upsertComment(deps, env, repo, number, body, marker) {
  const base = `${env.GITHUB_API_URL || "https://api.github.com"}/repos/${repo}/issues`;
  let existing;
  for (let page = 1; page <= COMMENT_PAGES && !existing; page++) {
    const comments = await api(deps, env, "GET", `${base}/${number}/comments?per_page=100&page=${page}`);
    // Only our own bot comment: a person pasting the marker must not get their comment rewritten.
    existing = comments.find((c) => typeof c.body === "string" && c.body.includes(marker) && c.user && c.user.type === "Bot");
    if (comments.length < 100) break;
  }
  if (existing) return api(deps, env, "PATCH", `${base}/comments/${existing.id}`, { body });
  return api(deps, env, "POST", `${base}/${number}/comments`, { body });
}

async function run(env, overrides = {}) {
  const deps = {
    log: (line) => console.log(line),
    exec: (command, args, options) =>
      execFileSync(command, args, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], maxBuffer: 64 * 1024 * 1024, ...options }),
    fetch: (...args) => fetch(...args),
    ...overrides,
  };
  const scanner = loadScanner(env, deps);
  for (const required of ["scanPath", "filterSummary", "changedFiles", "toMarkdown", "toGithubAnnotations", "toSarifString", "computeScore"]) {
    if (typeof scanner[required] !== "function") {
      throw new Error(
        `The installed security-hub-scanner is too old for this action (missing ${required}). ` +
          `Use version 0.5.0 or newer: set the action's "version" input accordingly.`,
      );
    }
  }
  const workspace = path.resolve(env.GITHUB_WORKSPACE || process.cwd());
  const target = path.resolve(workspace, env.INPUT_PATH || ".");
  if (!fs.existsSync(target)) throw new Error(`Input "path" does not exist: ${env.INPUT_PATH}`);

  const failOn = parseSeverity(env.INPUT_FAIL_ON, "fail-on");
  const minSeverity = parseSeverity(env.INPUT_SEVERITY, "severity");
  const event = readEvent(env);
  const isPullRequest = /^pull_request(_target)?$/.test(env.GITHUB_EVENT_NAME || "") && Boolean(event.pull_request);

  // 1. Which files does this change touch? (pull requests only)
  let changed;
  let scopeNote;
  if (isPullRequest && parseBool(env.INPUT_CHANGED_ONLY, true) && env.GITHUB_BASE_REF) {
    const baseRef = ensureBaseRef(env.GITHUB_BASE_REF, { ...deps, exec: (c, a) => deps.exec(c, a, { cwd: workspace }) });
    changed = scanner.changedFiles(target, baseRef);
    scopeNote = `Only the ${changed.length} file(s) changed in this pull request are listed; the whole project is scanned so flows across files are still found.`;
  }

  // 2. Scan everything, then narrow the report.
  const raw = scanner.scanPath(target, { ignore: parseList(env.INPUT_IGNORE), includeTests: parseBool(env.INPUT_INCLUDE_TESTS, false) });
  const summary = scanner.filterSummary(raw, { minSeverity, files: changed });
  const score = scanner.computeScore(summary);
  const findings = summary.results.flatMap((r) => r.findings);
  deps.log(`Scanned ${summary.filesScanned} file(s): ${findings.length} finding(s), score ${score.value}/100 (${score.label}).`);

  // 3. Inline annotations in the PR diff / the run page.
  for (const line of scanner.toGithubAnnotations(summary, { relativeTo: workspace })) deps.log(line);

  // 4. Job summary and sticky PR comment.
  const sha = (event.pull_request && event.pull_request.head && event.pull_request.head.sha) || env.GITHUB_SHA;
  const server = env.GITHUB_SERVER_URL || "https://github.com";
  const markdown = scanner.toMarkdown(summary, {
    relativeTo: workspace,
    scopeNote,
    linkBase: env.GITHUB_REPOSITORY && sha ? `${server}/${env.GITHUB_REPOSITORY}/blob/${sha}` : undefined,
  });
  appendFile(env.GITHUB_STEP_SUMMARY, markdown + "\n");

  if (isPullRequest && parseBool(env.INPUT_COMMENT, true) && env.INPUT_GITHUB_TOKEN && env.GITHUB_REPOSITORY) {
    try {
      await upsertComment(deps, env, env.GITHUB_REPOSITORY, event.pull_request.number, markdown, scanner.MARKDOWN_MARKER);
    } catch (err) {
      // Pull requests from forks get a read-only token: that must not break the check itself.
      deps.log(`::warning::Could not post the pull request comment (${firstLine(err)}). The annotations and job summary are still available.`);
    }
  }

  // 5. SARIF for GitHub code scanning (uploaded by a later step of action.yml).
  let sarifFile = "";
  if (parseBool(env.INPUT_SARIF, false)) {
    sarifFile = path.join(env.RUNNER_TEMP || os.tmpdir(), "security-testing-hub.sarif");
    fs.writeFileSync(sarifFile, scanner.toSarifString(summary.results, { relativeTo: workspace }));
  }

  // 6. Gate.
  const rank = { low: 0, medium: 1, high: 2, critical: 3 };
  const blocking = failOn ? findings.filter((f) => rank[f.severity] >= rank[failOn]) : [];
  if (blocking.length > 0) {
    deps.log(`::error::${blocking.length} finding(s) at or above "${failOn}" severity. Fix them, or mark reviewed ones with // security-hub-ignore.`);
  }

  const outputs = { score: String(score.value), findings: String(findings.length), failed: String(blocking.length > 0), "sarif-file": sarifFile };
  appendFile(env.GITHUB_OUTPUT, Object.entries(outputs).map(([key, value]) => `${key}=${value}\n`).join(""));
  return { outputs, summary, markdown };
}

module.exports = { run, parseList, parseBool, parseSeverity, VERSION_PATTERN };

if (require.main === module) {
  run(process.env).catch((err) => {
    console.log(`::error::${String((err && err.message) || err).replace(/\r?\n/g, " ")}`);
    process.exitCode = 1;
  });
}
