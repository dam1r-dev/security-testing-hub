import { execFileSync } from "child_process";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { runFix } from "../src/commands/fix";

// `security-hub fix`: a preview by default, --write only on a clean working tree, backups when there is no git.

const dirs: string[] = [];
afterAll(() => dirs.forEach((d) => fs.rmSync(d, { recursive: true, force: true })));
jest.setTimeout(60_000);

const APP = `const jwt = require("jsonwebtoken");\nmodule.exports = (id) => jwt.sign({ id }, process.env.JWT_SECRET);\n`;

function project(files: Record<string, string> = { "token.js": APP }): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "sh-fixcli-"));
  dirs.push(dir);
  fs.writeFileSync(path.join(dir, "package.json"), JSON.stringify({ dependencies: { jsonwebtoken: "9" } }));
  for (const [name, content] of Object.entries(files)) fs.writeFileSync(path.join(dir, name), content);
  return dir;
}

function git(dir: string, ...args: string[]): void {
  execFileSync("git", ["-c", "user.email=t@example.com", "-c", "user.name=t", "-c", "commit.gpgsign=false", ...args], { cwd: dir, stdio: "ignore" });
}

function committed(files?: Record<string, string>): string {
  const dir = project(files);
  git(dir, "init", "-q");
  git(dir, "add", "-A");
  git(dir, "commit", "-q", "-m", "init");
  return dir;
}

function run(dir: string, options: Parameters<typeof runFix>[1] = {}): { code: number; text: string } {
  const lines: string[] = [];
  const code = runFix(dir, options, (line) => lines.push(line));
  // eslint-disable-next-line no-control-regex
  return { code, text: lines.join("\n").replace(/\u001b\[[0-9;]*m/g, "") };
}

describe("security-hub fix", () => {
  it("shows a diff and changes nothing without --write", () => {
    const dir = project();
    const { code, text } = run(dir);
    expect(code).toBe(0);
    expect(text).toContain("--- a/token.js");
    expect(text).toContain('+module.exports = (id) => jwt.sign({ id }, process.env.JWT_SECRET, { expiresIn: "1h" });');
    expect(text).toContain("Nothing was changed. Run the same command with --write");
    expect(fs.readFileSync(path.join(dir, "token.js"), "utf8")).toBe(APP);
  });

  it("--write on a clean git working tree applies the fix and says how to review it", () => {
    const dir = committed();
    const { code, text } = run(dir, { write: true });
    expect(code).toBe(0);
    expect(fs.readFileSync(path.join(dir, "token.js"), "utf8")).toContain('{ expiresIn: "1h" }');
    expect(text).toContain("git diff");
    expect(text).toMatch(/Findings the fixer handles: 1 -> 0/);
    expect(fs.existsSync(path.join(dir, "token.js.security-hub.bak"))).toBe(false);
  });

  it("refuses to touch a file with uncommitted edits unless --force", () => {
    const dir = committed();
    fs.appendFileSync(path.join(dir, "token.js"), "// my unsaved idea\n");
    const refused = run(dir, { write: true });
    expect(refused.code).toBe(1);
    expect(fs.readFileSync(path.join(dir, "token.js"), "utf8")).not.toContain("expiresIn");
    const forced = run(dir, { write: true, force: true });
    expect(forced.code).toBe(0);
    expect(fs.readFileSync(path.join(dir, "token.js"), "utf8")).toContain("expiresIn");
  });

  it("without git, --write keeps a .security-hub.bak copy of every file it changes", () => {
    const dir = project();
    const { code, text } = run(dir, { write: true });
    expect(code).toBe(0);
    expect(fs.readFileSync(path.join(dir, "token.js.security-hub.bak"), "utf8")).toBe(APP);
    expect(text).toContain("not a git repository");
    expect(fs.readFileSync(path.join(dir, ".gitignore"), "utf8")).toContain("*.security-hub.bak"); // a backup holds the old secrets
  });

  it("--only limits the fix and rejects a rule that has none", () => {
    const dir = project({ "token.js": APP, "q.js": `app.get("/u", (req, res) => db.query("SELECT * FROM t WHERE a = '" + req.query.a + "'"));\n` });
    const onlyJwt = run(dir, { only: ["insecure-jwt"] });
    expect(onlyJwt.text).toContain("token.js");
    expect(onlyJwt.text).not.toContain("q.js");
    const bad = run(dir, { only: ["idor"] });
    expect(bad.code).toBe(2);
  });

  it("says so when there is nothing to fix, and lists what a person has to do", () => {
    const dir = project({ "ok.js": "module.exports = 1;\n" });
    expect(run(dir).text).toContain("Nothing to fix automatically.");
    const leftovers = project({ "p.js": `const jwt = require("jsonwebtoken");\napp.get("/p", (req, res) => res.json(jwt.decode(req.headers.authorization)));\n` });
    const { text } = run(leftovers);
    expect(text).toContain("Left for you (1)");
    expect(text).toContain("jwt.verify");
  });

  it("a missing path is a usage error", () => {
    expect(run(path.join(os.tmpdir(), "sh-does-not-exist-xyz")).code).toBe(2);
  });
});
