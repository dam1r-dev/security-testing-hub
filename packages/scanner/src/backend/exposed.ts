import * as fs from "fs";
import * as path from "path";
import { parseFile } from "../parsers/ast-parser";
import { findNodes } from "../parsers/utils";
import { gitState } from "../secrets/env-files";
import { applyInlineSuppressions } from "../suppress";
import { Finding, ScanResult, Severity } from "../types";

/**
 * Files that must never be reachable from the internet but sit in a folder the web server hands out:
 * `public/.env`, `public/backup.sql`, `static/id_rsa`, a whole `.git` folder, a service-account key.
 * Everything in `public/` (Next.js, Vite, CRA, Nuxt, Astro, Gatsby, SvelteKit), `static/`, `www/` and in any folder
 * passed to `express.static()` is served to every visitor as it is, at the same path.
 *
 * Also `express.static(".")` / `express.static(__dirname)` at the project root: that serves the whole project,
 * `.env` and the source code included.
 */

const STATIC_DIR_NAMES = new Set(["public", "static", "www", "wwwroot"]);
const MAX_DEPTH_FOR_STATIC_DIRS = 4;
const MAX_ENTRIES_PER_STATIC_DIR = 4000;
const MAX_SOURCE_FILES = 1500;
const MAX_CONTENT_BYTES = 200 * 1024;

const ENV_FILE = /^\.env(?:\.[\w.-]+)?$/;
const TEMPLATE_ENV_FILE = /\.(?:example|sample|template|dist|defaults?|schema)$/i;
const KEY_FILE = /\.(?:pem|key|p12|pfx|jks|keystore|ppk)$|^id_(?:rsa|dsa|ecdsa|ed25519)$/i;
const DATABASE_FILE = /\.(?:sqlite3?|db|mdb)$/i;
const SQL_FILE = /\.sql$/i;
const CREDENTIAL_NAME = /(?:^|[-_.])(?:credentials?|secrets?|service-?account|adminsdk|client[-_]secret)(?:[-_.]|$)/i;
// data formats only: a source file named secrets.ts that MENTIONS passwords is code, not a file of credentials
const CREDENTIAL_EXT = /\.(?:json|ya?ml|env|txt|ini|toml)$/i;
const AUTH_FILE = /^(?:\.htpasswd|\.netrc|\.pgpass|wp-config\.php)$/i;
const NPMRC = /^\.npmrc$/i;
const BACKUP_FILE = /(?:backup|dump|export|database|site|www)[^/\\]*\.(?:zip|tar|tgz|gz|7z|rar|bak|sql)$|\.(?:bak|backup|old|orig|swp)$|~$/i;
const VCS_DIR = new Set([".git", ".svn", ".hg"]);

interface Exposed {
  severity: Severity;
  what: string;
}

function readHead(file: string): string | undefined {
  try {
    const fd = fs.openSync(file, "r");
    try {
      const buffer = new Uint8Array(MAX_CONTENT_BYTES);
      const read = fs.readSync(fd, buffer, 0, MAX_CONTENT_BYTES, 0);
      return new TextDecoder("utf-8").decode(buffer.subarray(0, read));
    } finally {
      fs.closeSync(fd);
    }
  } catch {
    return undefined;
  }
}

/** Is this file one that must not be public? Looks at the name first and, for ambiguous names, at the content. */
function classify(file: string): Exposed | undefined {
  const name = path.basename(file);
  let size = 0;
  try {
    size = fs.statSync(file).size;
  } catch {
    return undefined;
  }
  if (size === 0) return undefined;

  if (ENV_FILE.test(name) && !TEMPLATE_ENV_FILE.test(name)) {
    const head = readHead(file) ?? "";
    return /^\s*(?:export\s+)?[A-Za-z_][\w.-]*\s*=\s*\S/m.test(head) ? { severity: "critical", what: "an environment file (its values are secrets)" } : undefined;
  }
  if (KEY_FILE.test(name)) {
    if (/\.(?:p12|pfx|jks|keystore|ppk)$/i.test(name)) return { severity: "critical", what: "a private key store" };
    const head = readHead(file) ?? "";
    return /PRIVATE KEY/.test(head) || /^id_/i.test(name) ? { severity: "critical", what: "a private key" } : undefined;
  }
  if (AUTH_FILE.test(name)) return { severity: "high", what: "a credentials file" };
  if (NPMRC.test(name)) return /_authToken|_password/.test(readHead(file) ?? "") ? { severity: "high", what: "an npm configuration with an auth token" } : undefined;
  if (CREDENTIAL_NAME.test(name) && CREDENTIAL_EXT.test(name)) {
    const head = readHead(file) ?? "";
    if (/private_key|BEGIN [A-Z ]*PRIVATE KEY/.test(head)) return { severity: "critical", what: "a service-account or private key file" };
    if (/client_secret|password|secret|token|api[_-]?key/i.test(head)) return { severity: "high", what: "a file of credentials" };
    return undefined;
  }
  if (DATABASE_FILE.test(name)) return { severity: "high", what: "a database file (every row can be downloaded)" };
  if (SQL_FILE.test(name) || BACKUP_FILE.test(name)) return { severity: "high", what: "a database dump or backup" };
  return undefined;
}

function makeFinding(file: string, severity: Severity, confidence: Finding["confidence"], message: string, shown: string, line = 1): Finding {
  return {
    ruleId: "exposed-files",
    severity,
    confidence,
    message,
    location: { file, startLine: line, startColumn: 1, endLine: line, endColumn: shown.length + 1 },
    sourceSnippet: shown,
    sinkSnippet: shown,
  };
}

function nearestPackageDir(from: string, limit: string): string | undefined {
  let dir = from;
  for (let depth = 0; depth < 10; depth++) {
    if (fs.existsSync(path.join(dir, "package.json"))) return dir;
    if (dir === limit) break;
    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return undefined;
}

function servesPublicFolder(packageDir: string | undefined): boolean {
  if (!packageDir) return false;
  try {
    const pkg = JSON.parse(fs.readFileSync(path.join(packageDir, "package.json"), "utf8"));
    return Object.keys({ ...pkg.dependencies, ...pkg.devDependencies }).some((d) =>
      /^(?:next|vite|react-scripts|nuxt|gatsby|astro|@sveltejs\/kit|@remix-run\/.+|@vue\/cli-service|parcel|express|fastify|koa|serve-static|sirv)$/.test(d),
    );
  } catch {
    return false;
  }
}

/** Static folders by name: any `public/`, `static/`, `www/`, `wwwroot/` up to a few levels down. */
function namedStaticDirs(root: string, skipDirs: Set<string>, isIgnored: (relative: string) => boolean): string[] {
  const found: string[] = [];
  const visit = (dir: string, depth: number): void => {
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      if (!entry.isDirectory() || skipDirs.has(entry.name) || entry.name.startsWith(".")) continue;
      const full = path.join(dir, entry.name);
      if (isIgnored(path.relative(root, full).split(path.sep).join("/"))) continue;
      if (STATIC_DIR_NAMES.has(entry.name)) found.push(full);
      else if (depth < MAX_DEPTH_FOR_STATIC_DIRS) visit(full, depth + 1);
    }
  };
  visit(root, 0);
  return found;
}

interface StaticCall {
  file: string;
  line: number;
  directory: string;
  text: string;
}

/** `express.static(...)` / `serveStatic(...)` calls whose argument can be worked out: a literal or path.join(__dirname, "x"). */
function staticCalls(root: string, skipDirs: Set<string>): StaticCall[] {
  const calls: StaticCall[] = [];
  const files: string[] = [];
  const stack = [root];
  while (stack.length > 0 && files.length < MAX_SOURCE_FILES) {
    const dir = stack.pop() as string;
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const entry of entries) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (!skipDirs.has(entry.name) && !entry.name.startsWith(".")) stack.push(full);
      } else if (entry.isFile() && /\.(?:[cm]?[jt]sx?)$/.test(entry.name)) files.push(full);
    }
  }
  // Real calls only: the words `express.static(".")` also appear in comments, messages and documentation strings (this
  // very scanner has them), and a regular expression over the text cannot tell the difference. Read the syntax tree.
  for (const file of files) {
    let text: string;
    try {
      if (fs.statSync(file).size > 512 * 1024) continue;
      text = fs.readFileSync(file, "utf8");
    } catch {
      continue;
    }
    if (!/express\.static|serveStatic/.test(text)) continue;
    let parsed;
    try {
      parsed = parseFile(file, text);
    } catch {
      continue;
    }
    if (!parsed) continue;
    for (const node of findNodes(parsed.tree.rootNode, (n) => n.type === "call_expression")) {
      const callee = node.childForFieldName("function")?.text ?? "";
      if (callee !== "express.static" && callee !== "serveStatic") continue;
      const argument = node.childForFieldName("arguments")?.namedChildren.find((a) => a.type !== "comment");
      if (!argument) continue;
      const directory = resolveStaticArgument(argument.text.trim(), path.dirname(file), root);
      if (directory !== undefined) calls.push({ file, line: node.startPosition.row + 1, directory, text: node.text.replace(/\s+/g, " ").slice(0, 80) });
    }
  }
  return calls;
}

/** "./public" -> that folder, path.join(__dirname, "..") -> the parent; anything else is unknown (undefined). */
function resolveStaticArgument(argument: string, fileDir: string, root: string): string | undefined {
  const literal = /^["'`]([^"'`]*)["'`]$/.exec(argument);
  if (literal) return path.resolve(root, literal[1] as string); // relative to the working directory = the project root
  if (/^__dirname$/.test(argument)) return fileDir;
  if (/^process\.cwd\(\)$/.test(argument)) return root;
  const joined = /^path\.(?:join|resolve)\(\s*(__dirname|process\.cwd\(\))\s*((?:,\s*["'`][^"'`]*["'`]\s*)*)\)$/.exec(argument);
  if (joined) {
    const base = joined[1] === "__dirname" ? fileDir : root;
    const segments = [...(joined[2] ?? "").matchAll(/["'`]([^"'`]*)["'`]/g)].map((s) => s[1] as string);
    return path.resolve(base, ...segments);
  }
  return undefined;
}

function walkStaticDir(dir: string, root: string, isIgnored: (relative: string) => boolean): Array<{ path: string; exposed: Exposed }> {
  const found: Array<{ path: string; exposed: Exposed }> = [];
  let seen = 0;
  const visit = (current: string, depth: number): void => {
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(current, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      if (++seen > MAX_ENTRIES_PER_STATIC_DIR) return;
      const full = path.join(current, entry.name);
      if (isIgnored(path.relative(root, full).split(path.sep).join("/"))) continue;
      if (entry.isDirectory()) {
        if (VCS_DIR.has(entry.name)) found.push({ path: full, exposed: { severity: "critical", what: `a ${entry.name} folder (the whole source code and every secret ever committed)` } });
        else if (entry.name !== "node_modules" && depth < 6) visit(full, depth + 1);
      } else if (entry.isFile()) {
        const exposed = classify(full);
        if (exposed) found.push({ path: full, exposed });
      }
    }
  };
  visit(dir, 0);
  return found;
}

export function scanExposedFiles(root: string, skipDirs: Set<string>, isIgnored: (relative: string) => boolean): ScanResult[] {
  const byFile = new Map<string, Finding[]>();
  const add = (file: string, finding: Finding): void => {
    byFile.set(file, [...(byFile.get(file) ?? []), finding]);
  };
  const reported = new Set<string>();

  const directories = new Map<string, "named" | "express">();
  for (const dir of namedStaticDirs(root, skipDirs, isIgnored)) directories.set(dir, "named");

  for (const call of staticCalls(root, skipDirs)) {
    const projectDir = nearestPackageDir(path.dirname(call.file), root) ?? root;
    if (path.resolve(call.directory) === path.resolve(projectDir)) {
      const shown = call.text;
      add(
        call.file,
        makeFinding(
          call.file,
          "critical",
          "high",
          `${shown}... serves the whole project folder to the internet: /.env, /package.json and every source file can be downloaded by URL. ` +
            `Serve a dedicated folder that holds only public files (express.static(path.join(__dirname, "public"))) and move the rest out of it.`,
          shown,
          call.line,
        ),
      );
    } else if (fs.existsSync(call.directory) && fs.statSync(call.directory).isDirectory()) {
      directories.set(call.directory, "express");
    }
  }

  for (const [dir] of directories) {
    const projectDir = nearestPackageDir(dir, root);
    const confidence: Finding["confidence"] = servesPublicFolder(projectDir) ? "high" : "medium";
    for (const { path: file, exposed } of walkStaticDir(dir, root, isIgnored)) {
      if (reported.has(file)) continue;
      reported.add(file);
      const isFolder = fs.statSync(file).isDirectory();
      // a file git ignores is not deployed from the repository (Vercel, Netlify, GitHub Pages build from git)
      if (!isFolder && gitState(file, root) === "ignored") continue;
      const served = "/" + path.relative(dir, file).split(path.sep).join("/");
      const label = path.relative(root, file).split(path.sep).join("/") || path.basename(file);
      add(
        file,
        makeFinding(
          file,
          exposed.severity,
          confidence,
          `${label} is ${exposed.what}, and it sits in ${path.basename(dir)}/, which the web server hands out as it is: anyone can download it at ${served}. ` +
            `Move it out of ${path.basename(dir)}/ now, rotate every secret it contained (removing it is not enough if it was ever deployed or committed), ` +
            `and keep only files meant for visitors in that folder.`,
          path.basename(file),
        ),
      );
    }
  }

  const results: ScanResult[] = [];
  for (const [file, findings] of byFile) {
    let source = "";
    try {
      if (fs.statSync(file).isFile() && /\.(?:[cm]?[jt]sx?)$/.test(file)) source = fs.readFileSync(file, "utf8");
    } catch {
      source = "";
    }
    const { kept, suppressed } = applyInlineSuppressions(findings, source);
    const result: ScanResult = { file, findings: kept };
    if (suppressed > 0) result.suppressed = suppressed;
    results.push(result);
  }
  return results;
}
