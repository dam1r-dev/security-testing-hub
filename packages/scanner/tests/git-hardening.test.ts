import { execFileSync } from "child_process";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { changedFiles } from "../src/index";

// A folder somebody else made can carry its own git config. `core.fsmonitor` is a command git runs on status / diff:
// scanning such a folder must not run it.

const dirs: string[] = [];
afterAll(() => dirs.forEach((d) => fs.rmSync(d, { recursive: true, force: true })));
jest.setTimeout(60_000);

function git(dir: string, ...args: string[]): void {
  execFileSync("git", ["-c", "user.email=t@example.com", "-c", "user.name=t", "-c", "commit.gpgsign=false", ...args], { cwd: dir, stdio: "ignore" });
}

describe("git calls inside a folder that carries a hostile git config", () => {
  it("do not run core.fsmonitor", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "sh-git-"));
    dirs.push(dir);
    git(dir, "init", "-q");
    fs.writeFileSync(path.join(dir, "a.js"), "const a = 1;\n");
    git(dir, "add", "-A");
    git(dir, "commit", "-q", "-m", "one");
    fs.writeFileSync(path.join(dir, "a.js"), "const a = 2;\n");
    git(dir, "add", "-A");
    git(dir, "commit", "-q", "-m", "two");

    const marker = path.join(dir, "..", `fsmonitor-ran-${path.basename(dir)}`);
    const hook = path.join(dir, "..", `hook-${path.basename(dir)}.js`);
    dirs.push(marker, hook);
    fs.writeFileSync(hook, `require("fs").writeFileSync(${JSON.stringify(marker)}, "ran");\nprocess.stdout.write("\0");\n`);
    const command = `"${process.execPath.split("\\").join("/")}" "${hook.split("\\").join("/")}"`;
    git(dir, "config", "core.fsmonitor", command);

    // precondition: plain git really does run the hook here (it depends on the git version and platform)
    try {
      execFileSync("git", ["status", "--porcelain"], { cwd: dir, stdio: "ignore" });
    } catch {
      // a failing hook is fine: only whether it ran matters
    }
    const hookRunsWithPlainGit = fs.existsSync(marker);
    fs.rmSync(marker, { force: true });
    if (!hookRunsWithPlainGit) return;

    expect(changedFiles(dir, "HEAD~1")).toEqual([path.join(dir, "a.js")]);
    expect(fs.existsSync(marker)).toBe(false);
  });
});
