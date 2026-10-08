import * as fs from "fs";
import * as os from "os";
import * as path from "path";

let dir: string | undefined;

/**
 * A path inside a throwaway project whose package.json declares session-cookie auth, so the rules that only
 * make sense for cookie-authenticated apps (CSRF, IDOR) apply. Tests that scan virtual files such as
 * "app.js" would otherwise inherit the scanner's own package.json, which has no authentication library.
 */
export function cookieProjectFile(relative: string): string {
  if (!dir) {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "sh-cookie-project-"));
    fs.writeFileSync(path.join(dir, "package.json"), JSON.stringify({ dependencies: { "express-session": "1.18.0" } }));
    process.on("exit", () => fs.rmSync(dir as string, { recursive: true, force: true }));
  }
  return path.join(dir, relative);
}

const projects = new Map<string, string>();

/** A path inside a throwaway project whose package.json declares exactly these dependencies. */
export function projectFile(dependencies: Record<string, string>, relative: string): string {
  const key = JSON.stringify(dependencies);
  let projectDir = projects.get(key);
  if (!projectDir) {
    projectDir = fs.mkdtempSync(path.join(os.tmpdir(), "sh-project-"));
    fs.writeFileSync(path.join(projectDir, "package.json"), JSON.stringify({ dependencies }));
    projects.set(key, projectDir);
    process.on("exit", () => fs.rmSync(projectDir as string, { recursive: true, force: true }));
  }
  return path.join(projectDir, relative);
}
