import { execFileSync } from "child_process";
import * as fs from "fs";
import * as path from "path";

function git(cwd: string, args: string[]): string {
  return execFileSync("git", args, {
    cwd,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
    maxBuffer: 64 * 1024 * 1024,
  });
}

/**
 * Files added, copied, modified or renamed between `baseRef` and HEAD, as absolute paths.
 * Uses the merge-base (`base...HEAD`, what a pull request shows) and falls back to a plain
 * `base HEAD` diff when there is no common ancestor in the local history.
 */
export function changedFiles(directory: string, baseRef: string): string[] {
  if (baseRef.startsWith("-")) throw new Error(`Invalid git ref "${baseRef}".`);
  let topLevel: string;
  try {
    topLevel = git(directory, ["rev-parse", "--show-toplevel"]).trim();
  } catch {
    throw new Error(`"${directory}" is not inside a git repository, so changed files can't be determined.`);
  }

  const diff = (range: string): string[] =>
    git(topLevel, ["diff", "--name-only", "--diff-filter=ACMR", "-z", range, "--"])
      .split("\0")
      .filter((name) => name !== "");

  let names: string[];
  try {
    names = diff(`${baseRef}...HEAD`);
  } catch {
    try {
      names = diff(`${baseRef}..HEAD`);
    } catch (err) {
      const detail = err instanceof Error ? err.message.split("\n")[0] : String(err);
      throw new Error(
        `Could not diff against "${baseRef}" (${detail}). In CI, fetch the base branch first ` +
          `(actions/checkout with fetch-depth: 0).`,
      );
    }
  }
  // Report paths the way the caller spells them: git prints the real path of the repository
  // (/private/var/... on macOS, a long Windows name), the caller may have given a symlink or a short name.
  let root = topLevel;
  try {
    const relativeToRepo = path.relative(fs.realpathSync.native(directory), fs.realpathSync.native(topLevel));
    root = path.resolve(directory, relativeToRepo);
  } catch {
    // fall back to git's spelling
  }
  return names.map((name) => path.resolve(root, name));
}
