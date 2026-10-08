import { execFileSync } from "child_process";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";

// The action's entry point is plain JS outside the TypeScript packages.
// eslint-disable-next-line @typescript-eslint/no-require-imports
const action = require("../../../action/run.js");
// eslint-disable-next-line @typescript-eslint/no-require-imports
const scanner = require("security-hub-scanner");

interface Call {
  method: string;
  url: string;
  body?: { body: string };
}

const VULNERABLE = (name: string) => `app.get("/${name}", (req, res) => { db.query("SELECT " + req.query.${name}); });\n`;

describe("GitHub Action orchestrator (action/run.js)", () => {
  let dir: string;
  let outputFile: string;
  let summaryFile: string;
  let logs: string[];
  let calls: Call[];

  const git = (...args: string[]) =>
    execFileSync("git", ["-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false", ...args], {
      cwd: dir,
      stdio: "pipe",
      encoding: "utf8",
    });
  const write = (rel: string, source: string) => {
    fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
    fs.writeFileSync(path.join(dir, rel), source);
  };

  /** A fake GitHub API. `existing` = comments already on the pull request. */
  const fakeFetch =
    (existing: Array<{ id: number; body: string; user: { type: string } }> = [], status = 200) =>
    async (url: string, init: { method: string; body?: string }) => {
      calls.push({ method: init.method, url, body: init.body ? JSON.parse(init.body) : undefined });
      return {
        ok: status < 400,
        status,
        json: async () => (init.method === "GET" ? existing : { id: 99 }),
      };
    };

  const baseEnv = (extra: Record<string, string> = {}) => ({
    GITHUB_WORKSPACE: dir,
    GITHUB_OUTPUT: outputFile,
    GITHUB_STEP_SUMMARY: summaryFile,
    GITHUB_REPOSITORY: "o/r",
    GITHUB_SHA: "deadbeef",
    GITHUB_EVENT_NAME: "pull_request",
    GITHUB_BASE_REF: "main",
    GITHUB_EVENT_PATH: path.join(dir, ".event.json"),
    RUNNER_TEMP: dir,
    INPUT_PATH: ".",
    INPUT_GITHUB_TOKEN: "t0ken",
    ...extra,
  });

  const exec = (env: Record<string, string>, fetchImpl = fakeFetch()) =>
    action.run(env, { scanner, fetch: fetchImpl, log: (line: string) => logs.push(line) });

  const outputs = (): Record<string, string> =>
    Object.fromEntries(
      fs
        .readFileSync(outputFile, "utf8")
        .split("\n")
        .filter(Boolean)
        .map((l) => [l.slice(0, l.indexOf("=")), l.slice(l.indexOf("=") + 1)]),
    );

  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "sh-action-"));
    outputFile = path.join(dir, ".gh-output");
    summaryFile = path.join(dir, ".gh-summary");
    logs = [];
    calls = [];
    git("init", "-q");
    git("checkout", "-q", "-b", "main");
    write("src/old.js", VULNERABLE("old"));
    write(".gitignore", ".gh-*\n.event.json\n*.sarif\n");
    git("add", "-A");
    git("commit", "-q", "-m", "base");
    git("update-ref", "refs/remotes/origin/main", "main"); // what `git fetch origin main` would leave behind
    git("checkout", "-q", "-b", "feature");
    write("src/new.js", VULNERABLE("added"));
    git("add", "-A");
    git("commit", "-q", "-m", "change");
    fs.writeFileSync(
      path.join(dir, ".event.json"),
      JSON.stringify({ pull_request: { number: 7, head: { sha: "abc123" } } }),
    );
  });
  afterEach(() => fs.rmSync(dir, { recursive: true, force: true }));

  it("on a pull request: scans everything, reports only the changed files, annotates and comments", async () => {
    await exec(baseEnv());

    expect(outputs()).toMatchObject({ findings: "1", failed: "false" });
    const annotations = logs.filter((l) => l.startsWith("::error") || l.startsWith("::warning"));
    expect(annotations).toHaveLength(1);
    expect(annotations[0]).toContain("file=src/new.js,line=1");

    expect(calls.map((c) => c.method)).toEqual(["GET", "POST"]);
    expect(calls[1]?.url).toBe("https://api.github.com/repos/o/r/issues/7/comments");
    const comment = calls[1]?.body?.body ?? "";
    expect(comment).toContain("<!-- security-testing-hub-report -->");
    expect(comment).toContain("src/new.js:1");
    expect(comment).not.toContain("src/old.js");
    expect(comment).toContain("https://github.com/o/r/blob/abc123/src/new.js#L1");
    expect(comment).toContain("1 more finding(s) in files this change does not touch");
    expect(fs.readFileSync(summaryFile, "utf8")).toContain("Security Testing Hub");
  });

  it("with changed-only off, reports the whole project", async () => {
    await exec(baseEnv({ INPUT_CHANGED_ONLY: "false" }));
    expect(outputs().findings).toBe("2");
  });

  it("updates its own earlier comment instead of posting a new one", async () => {
    const marker = "<!-- security-testing-hub-report -->";
    await exec(baseEnv(), fakeFetch([{ id: 41, body: `${marker}\nold`, user: { type: "Bot" } }]));
    expect(calls.map((c) => `${c.method} ${c.url.split("/issues/")[1]}`)).toEqual(["GET 7/comments?per_page=100&page=1", "PATCH comments/41"]);
  });

  it("never rewrites a comment a person wrote, even if it contains the marker", async () => {
    const marker = "<!-- security-testing-hub-report -->";
    await exec(baseEnv(), fakeFetch([{ id: 5, body: `${marker} look`, user: { type: "User" } }]));
    expect(calls.map((c) => c.method)).toEqual(["GET", "POST"]);
  });

  it("only warns when the token can't comment (pull requests from forks)", async () => {
    await exec(baseEnv(), fakeFetch([], 403));
    expect(logs.some((l) => l.startsWith("::warning::Could not post the pull request comment"))).toBe(true);
    expect(outputs().findings).toBe("1"); // the check itself still completed
  });

  it("does not comment when comment is off or there is no token", async () => {
    await exec(baseEnv({ INPUT_COMMENT: "false" }));
    await exec(baseEnv({ INPUT_GITHUB_TOKEN: "" }));
    expect(calls).toHaveLength(0);
  });

  it("flags the run as failed only when a reported finding reaches fail-on", async () => {
    await exec(baseEnv({ INPUT_FAIL_ON: "critical" }));
    expect(outputs().failed).toBe("true");
    expect(logs.some((l) => l.startsWith("::error::1 finding(s) at or above \"critical\""))).toBe(true);

    fs.writeFileSync(outputFile, "");
    await exec(baseEnv({ INPUT_FAIL_ON: "critical", INPUT_SEVERITY: "critical", INPUT_PATH: "src/../src" }));
    expect(outputs().failed).toBe("true");

    fs.writeFileSync(outputFile, "");
    git("checkout", "-q", "main"); // nothing changed relative to main: the old bug is not this PR's business
    await exec(baseEnv({ INPUT_FAIL_ON: "critical" }));
    expect(outputs()).toMatchObject({ findings: "0", failed: "false" });
  });

  it("on a push (no pull request): full report, no base-branch lookup, no comment", async () => {
    await exec(baseEnv({ GITHUB_EVENT_NAME: "push", GITHUB_BASE_REF: "" }));
    expect(outputs().findings).toBe("2");
    expect(calls).toHaveLength(0);
  });

  it("writes SARIF with repository-relative paths when asked", async () => {
    await exec(baseEnv({ INPUT_SARIF: "true", INPUT_CHANGED_ONLY: "false" }));
    const file = outputs()["sarif-file"] ?? "";
    expect(file).toMatch(/security-testing-hub\.sarif$/);
    const sarif = JSON.parse(fs.readFileSync(file, "utf8"));
    const uris = sarif.runs[0].results.map((r: { locations: Array<{ physicalLocation: { artifactLocation: { uri: string } } }> }) => r.locations[0]?.physicalLocation.artifactLocation.uri).sort();
    expect(uris).toEqual(["src/new.js", "src/old.js"]);
  });

  it("honours ignore patterns and counts what comments hide", async () => {
    write("src/third.js", `app.get("/t", (req, res) => {\n  // security-hub-ignore\n  db.query("SELECT " + req.query.t);\n});\n`);
    git("add", "-A");
    git("commit", "-q", "-m", "third");
    await exec(baseEnv({ INPUT_IGNORE: "# comment\nsrc/new.js\n" }));
    expect(outputs().findings).toBe("0");
    expect(calls[1]?.body?.body).toContain("1 finding(s) hidden by `security-hub-ignore` comments");
  });

  it("rejects bad inputs with a clear message instead of running", async () => {
    await expect(exec(baseEnv({ INPUT_VERSION: "1.0.0; rm -rf /" }))).rejects.toThrow(/Input "version"/);
    await expect(exec(baseEnv({ INPUT_VERSION: "--registry=http://evil" }))).rejects.toThrow(/Input "version"/);
    await expect(exec(baseEnv({ INPUT_FAIL_ON: "severe" }))).rejects.toThrow(/Input "fail-on"/);
    await expect(exec(baseEnv({ INPUT_PATH: "nope" }))).rejects.toThrow(/Input "path" does not exist/);
  });

  it("parses list and boolean inputs", () => {
    expect(action.parseList("a\n\n# c\n  b  \r\n")).toEqual(["a", "b"]);
    expect(action.parseBool("TRUE", false)).toBe(true);
    expect(action.parseBool("", true)).toBe(true);
    expect(action.parseBool("no", true)).toBe(false);
    expect(action.VERSION_PATTERN.test("0.4.0")).toBe(true);
    expect(action.VERSION_PATTERN.test("latest")).toBe(true);
  });

  describe("action.yml and workflows", () => {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const yaml = require("js-yaml");
    const root = path.resolve(__dirname, "../../..");
    const load = (rel: string) => yaml.load(fs.readFileSync(path.join(root, rel), "utf8"));

    it("action.yml is valid and wires every input the script reads", () => {
      const definition = load("action.yml");
      expect(definition.runs.using).toBe("composite");
      const source = fs.readFileSync(path.join(root, "action/run.js"), "utf8");
      const readByScript = [...source.matchAll(/env\.INPUT_([A-Z_]+)/g)].map((m) => (m[1] ?? "").toLowerCase().replace(/_/g, "-"));
      for (const name of new Set(readByScript)) expect(Object.keys(definition.inputs)).toContain(name);
      const scanStep = definition.runs.steps.find((step: { id?: string }) => step.id === "scan");
      for (const name of Object.keys(definition.inputs)) {
        expect(scanStep.env[`INPUT_${name.toUpperCase().replace(/-/g, "_")}`]).toBe(`\${{ inputs.${name} }}`);
      }
    });

    it("never interpolates inputs into shell text", () => {
      const definition = load("action.yml");
      for (const step of definition.runs.steps) {
        if (typeof step.run === "string") expect(step.run).not.toMatch(/\$\{\{\s*inputs\./);
      }
    });

    it("the repository's own workflows parse", () => {
      for (const file of ["security.yml", "ci.yml", "publish.yml"]) {
        expect(load(`.github/workflows/${file}`).jobs).toBeDefined();
      }
    });
  });
});
