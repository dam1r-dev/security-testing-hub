import * as fs from "fs";
import * as path from "path";
import { languageForExtension, parseFile } from "../parsers/ast-parser";
import { gitState } from "../secrets/env-files";
import { Finding, ScanSummary } from "../types";
import { appendDiff, applyEdits, newFileDiff, unifiedDiff } from "./diff";
import { callAt, corsEdit, expiryEdit, jwtOptionEdits } from "./jwt";
import { rlsMigration, tablesWithoutRls } from "./rls";
import { envLine, offsetOf, secretFix } from "./secrets";
import { hasDependency, placeholderStyle, sqlEdit } from "./sql";
import { FIXABLE_RULES, FixOptions, FixPlan, TextEdit } from "./types";

export { FIXABLE_RULES } from "./types";
export type { FixOptions, FixPlan, TextEdit, FileWrite } from "./types";

const SOURCE_EXTENSION = /\.(?:[cm]?[jt]sx?)$/i;

function projectRootOf(file: string, scanRoot: string): string {
  let dir = path.dirname(path.resolve(file));
  for (let depth = 0; depth < 10; depth++) {
    if (fs.existsSync(path.join(dir, "package.json"))) return dir;
    if (dir === path.resolve(scanRoot)) break;
    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return path.resolve(scanRoot);
}

const BROWSER_FRAMEWORK = /^(?:@angular\/core|react-scripts|vite|vue|svelte|solid-js|preact|@vue\/cli-service|parcel)$/;
const SERVER_FRAMEWORK = /^(?:next|nuxt|express|fastify|koa|hono|@nestjs\/core|@remix-run\/.+|@sveltejs\/kit|@hapi\/hapi|restify|@trpc\/server|firebase-functions|serverless|astro)$/;

/** A single-page app: a browser framework and nothing that runs on a server. */
function runsOnlyInTheBrowser(file: string): boolean {
  return hasDependency(file, BROWSER_FRAMEWORK) && !hasDependency(file, SERVER_FRAMEWORK);
}

function readOrEmpty(file: string): string {
  try {
    return fs.readFileSync(file, "utf8");
  } catch {
    return "";
  }
}

function hasLine(text: string, pattern: RegExp): boolean {
  return text.split(/\r?\n/).some((l) => pattern.test(l.trim()));
}

/** The `supabase/migrations` folder for a SQL file that is part of a Supabase project. */
function migrationsFolderFor(file: string): string {
  const directory = path.dirname(file);
  if (path.basename(directory) === "migrations") return directory;
  for (let dir = directory, depth = 0; depth < 8; depth++) {
    if (path.basename(dir) === "supabase") return path.join(dir, "migrations");
    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return directory;
}

/**
 * Works out the automatic fixes for what a scan found. Nothing is written: the plan says what WOULD change, so a
 * person can read it (`renderPlan`) before `applyPlan` touches a file.
 */
export function planFixes(summary: ScanSummary, scanRoot: string, options: FixOptions = {}): FixPlan {
  const plan: FixPlan = { originals: {}, edits: [], writes: [], todo: [], skipped: [], manual: 0 };
  const wanted = (rule: string): boolean => !options.only || options.only.includes(rule);
  const allFindings = summary.results.flatMap((r) => r.findings);
  const byFile = new Map<string, Finding[]>();
  for (const finding of allFindings) byFile.set(finding.location.file, [...(byFile.get(finding.location.file) ?? []), finding]);

  const seen = new Set<string>(); // "kind:file:offset": the same call is fixed once, however many findings point at it
  const secretNames = new Map<string, Map<string, string>>(); // project root -> name -> value
  const envNames = new Map<string, Set<string>>(); // project root -> names for .env.example
  const secretsMoved = new Map<string, Map<string, string | undefined>>(); // project root -> name -> value (undefined: write only the name)
  let rotateCount = 0;
  let corsEnv = false;

  const addEdit = (edit: TextEdit): void => {
    const key = `${edit.file}:${edit.start}:${edit.end}:${edit.text}`;
    if (seen.has(key)) return;
    seen.add(key);
    plan.edits.push(edit);
  };

  for (const [file, findings] of byFile) {
    const fixable = findings.filter((f) => (FIXABLE_RULES as readonly string[]).includes(f.ruleId) && f.ruleId !== "supabase-rls" && wanted(f.ruleId));
    if (fixable.length === 0 || !SOURCE_EXTENSION.test(file) || !languageForExtension(path.extname(file))) continue;
    const source = readOrEmpty(file);
    let parsed;
    try {
      parsed = parseFile(file, source);
    } catch {
      parsed = undefined;
    }
    if (!parsed) continue;
    const root = parsed.tree.rootNode;
    const isTypeScript = /\.tsx?$/i.test(file);
    const projectRoot = projectRootOf(file, scanRoot);
    const taken = secretNames.get(projectRoot) ?? new Map<string, string>();
    secretNames.set(projectRoot, taken);
    const style = placeholderStyle(file);

    for (const finding of fixable) {
      const skip = (reason: string): void => {
        plan.skipped.push({ finding, reason });
      };
      const { startLine, startColumn } = finding.location;

      if (finding.ruleId === "sql-injection") {
        const call = callAt(root, startLine, startColumn);
        if (!call) {
          skip("the flagged call could not be found again in the file");
          continue;
        }
        const key = `sql:${file}:${call.startIndex}`;
        if (seen.has(key)) continue;
        const edit = sqlEdit(call, file, style);
        if ("reason" in edit) skip(edit.reason);
        else {
          seen.add(key);
          addEdit(edit);
          plan.originals[file] = source;
        }
      } else if (finding.ruleId === "insecure-jwt") {
        const call = callAt(root, startLine, startColumn);
        if (!call) {
          skip("the flagged call could not be found again in the file");
          continue;
        }
        const snippet = finding.sourceSnippet;
        if (snippet === "no expiresIn / exp" || snippet === "no setExpirationTime") {
          const key = `exp:${file}:${call.startIndex}`;
          if (seen.has(key)) continue;
          seen.add(key);
          const edit = expiryEdit(call, file, source);
          if ("reason" in edit) skip(edit.reason);
          else {
            addEdit(edit);
            plan.originals[file] = source;
            plan.todo.push(`Tokens now expire after 1 hour (${(path.relative(scanRoot, file) || file).split(path.sep).join("/")}): check that signed-in users can sign in again, or add a refresh flow.`);
          }
        } else if (snippet === "decode without verify") {
          skip("jwt.decode() needs to become jwt.verify() with your secret and a decision about what to do when it fails");
        } else {
          const key = `jwtopt:${file}:${call.startIndex}`;
          if (seen.has(key)) continue;
          seen.add(key);
          const edits = jwtOptionEdits(call, file, source);
          if (edits.length === 0) skip("the options are not written out in the call");
          for (const edit of edits) addEdit(edit);
          if (edits.length > 0) plan.originals[file] = source;
        }
      } else if (finding.ruleId === "insecure-cors") {
        const call = callAt(root, startLine, startColumn);
        if (!call || !/^origin:/.test(finding.sourceSnippet)) {
          skip("the origin is written by hand in headers; replace it with a check against a list of allowed origins");
          continue;
        }
        const key = `cors:${file}:${call.startIndex}`;
        if (seen.has(key)) continue;
        seen.add(key);
        const edit = corsEdit(call, file);
        if ("reason" in edit) skip(edit.reason);
        else {
          addEdit(edit);
          plan.originals[file] = source;
          envNames.set(projectRoot, (envNames.get(projectRoot) ?? new Set()).add("ALLOWED_ORIGINS"));
          corsEnv = true;
        }
      } else if (finding.ruleId === "hardcoded-secret") {
        if (/^\.env/.test(path.basename(file))) continue; // not source code: handled below
        if (/browser-exposed variable|committed to git/.test(finding.message)) {
          skip("rename the variable without the public prefix and keep the value out of git by hand");
          continue;
        }
        if (runsOnlyInTheBrowser(file)) {
          skip("this project is a browser app (no server framework in package.json), where an environment variable would be public too: the secret has to move to a server");
          continue;
        }
        if (/^\s*["']use client["']/.test(source)) {
          skip("this file runs in the browser, where an environment variable would be public too: move the call to server code first");
          continue;
        }
        const offset = offsetOf(source, startLine, startColumn);
        if (offset < 0) {
          skip("the position of the secret could not be found again");
          continue;
        }
        const fix = secretFix(root, file, offset, isTypeScript, taken);
        if ("reason" in fix) {
          skip(fix.reason);
          continue;
        }
        addEdit(fix.edit);
        plan.originals[file] = source;
        rotateCount++;
        const moved = secretsMoved.get(projectRoot) ?? new Map<string, string | undefined>();
        moved.set(fix.name, fix.value);
        secretsMoved.set(projectRoot, moved);
        envNames.set(projectRoot, (envNames.get(projectRoot) ?? new Set()).add(fix.name));
      }
    }
  }

  // Supabase: one migration for every table found open.
  if (wanted("supabase-rls")) {
    const tables = tablesWithoutRls(allFindings.filter((f) => f.ruleId === "supabase-rls"));
    if (tables.length > 0) {
      const first = tables[0] as { table: string; file: string };
      const migration = rlsMigration([{ ...first, file: path.join(migrationsFolderFor(first.file), "x.sql") }, ...tables.slice(1)]);
      if (migration) {
        plan.writes.push(migration);
        plan.todo.push("Supabase: write the policies your app needs (the migration carries an example per table) BEFORE you deploy it: with RLS on and no policy, the browser can no longer read or write those tables.");
      }
    }
  }

  // Environment files: .env.example gets the names, .env the values (never printed), .gitignore keeps .env out of git.
  for (const [projectRoot, names] of envNames) {
    const example = path.join(projectRoot, ".env.example");
    const exampleOriginal = readOrEmpty(example);
    const missing = [...names].filter((name) => !hasLine(exampleOriginal, new RegExp(`^${name}=`)));
    if (missing.length > 0) {
      const separator = exampleOriginal === "" || exampleOriginal.endsWith("\n") ? "" : "\n";
      const content = `${exampleOriginal}${separator}${missing.map((n) => `${n}=`).join("\n")}\n`;
      plan.originals[example] = exampleOriginal;
      plan.writes.push({ file: example, content, shown: content, created: !fs.existsSync(example), note: `lists ${missing.join(", ")} (names only) in .env.example` });
    }

    const moved = secretsMoved.get(projectRoot);
    if (moved && moved.size > 0) {
      const gitignore = path.join(projectRoot, ".gitignore");
      const ignoreOriginal = readOrEmpty(gitignore);
      if (!hasLine(ignoreOriginal, /^\/?\.env(?:\*|\.local|\.\*)?$/)) {
        const separator = ignoreOriginal === "" || ignoreOriginal.endsWith("\n") ? "" : "\n";
        const content = `${ignoreOriginal}${separator}.env\n`;
        plan.originals[gitignore] = ignoreOriginal;
        plan.writes.push({ file: gitignore, content, shown: content, created: !fs.existsSync(gitignore), note: "keeps .env out of git" });
      }

      const envFile = path.join(projectRoot, ".env");
      const state = fs.existsSync(envFile) ? gitState(envFile, projectRoot) : "not-ignored";
      const envOriginal = readOrEmpty(envFile);
      const additions = [...moved].filter(([name]) => !hasLine(envOriginal, new RegExp(`^${name}=`)));
      if (state === "tracked") {
        plan.todo.push(`.env is tracked by git: run \`git rm --cached .env\` first, then put the secret values in it yourself (the fixer did not write them).`);
      } else if (additions.length > 0) {
        const withValue = additions.filter(([, value]) => value !== undefined) as Array<[string, string]>;
        const withoutValue = additions.filter(([, value]) => value === undefined).map(([name]) => name);
        if (withValue.length > 0) {
          const separator = envOriginal === "" || envOriginal.endsWith("\n") ? "" : "\n";
          const content = `${envOriginal}${separator}${withValue.map(([name, value]) => envLine(name, value)).join("\n")}\n`;
          const shown = `${envOriginal.replace(/=.*/g, "=<hidden>")}${separator}${withValue.map(([name]) => `${name}=<the value moved out of your source code>`).join("\n")}\n`;
          plan.originals[envFile] = envOriginal;
          plan.writes.push({ file: envFile, content, shown, created: !fs.existsSync(envFile), note: `keeps the secret value(s) in .env: ${withValue.map(([n]) => n).join(", ")}` });
        }
        if (withoutValue.length > 0) plan.todo.push(`Put the value of ${withoutValue.join(", ")} into .env by hand (it has characters the fixer does not copy).`);
      }
    }
  }
  if (corsEnv) plan.todo.push("Set ALLOWED_ORIGINS (comma separated, e.g. https://app.example.com) in your environment: until you do, no other origin may call this server.");
  if (rotateCount > 0) {
    plan.todo.unshift(
      `ROTATE ${rotateCount} secret(s): the old value stays in your git history and in every copy of the repository, so treat it as leaked: create a new key at the provider (or a new random secret) and put THAT in .env. Load .env in your app (Next.js and Vite do it by themselves; plain Node needs \`import "dotenv/config"\`).`,
    );
  }

  const fixedRules = new Set<string>(FIXABLE_RULES);
  plan.manual = allFindings.filter((f) => !fixedRules.has(f.ruleId) || !wanted(f.ruleId)).length;
  return plan;
}

/** The text a person reads before agreeing: one diff per file, then what is left to do by hand. */
export function renderPlan(plan: FixPlan, root: string): string {
  const rel = (file: string): string => path.relative(root, file).split(path.sep).join("/") || path.basename(file);
  const out: string[] = [];
  const editsByFile = new Map<string, TextEdit[]>();
  for (const edit of plan.edits) editsByFile.set(edit.file, [...(editsByFile.get(edit.file) ?? []), edit]);

  for (const [file, edits] of editsByFile) {
    out.push(unifiedDiff(rel(file), plan.originals[file] ?? "", edits), "");
    for (const edit of [...edits].sort((a, b) => a.start - b.start)) out.push(`  # ${edit.note}`);
    out.push("");
  }
  for (const write of plan.writes) {
    out.push(write.created ? newFileDiff(rel(write.file), write.shown) : appendDiff(rel(write.file), plan.originals[write.file] ?? "", write.shown), `  # ${write.note}`, "");
  }
  let text = out.join("\n").replace(/\r/g, "");
  // a diff shows the lines it removes: a secret must not be printed there
  for (const edit of plan.edits) if (edit.secret && edit.secret.length >= 4) text = text.split(edit.secret).join("<hidden>");
  return text;
}

export interface ApplyOptions {
  /** Copy each existing file to `<file>.security-hub.bak` before changing it (for projects without git). */
  backup?: boolean;
  /** The project folder: where `.gitignore` gets a line for the backups, so they are never committed. */
  root?: string;
}

const BACKUP_PATTERN = "*.security-hub.bak";

/** A backup holds the OLD file, secrets included: it must not be committed by the next `git add .`. */
function ignoreBackups(root: string): void {
  const gitignore = path.join(root, ".gitignore");
  const current = readOrEmpty(gitignore);
  if (current.split(/\r?\n/).some((line) => line.trim() === BACKUP_PATTERN)) return;
  const separator = current === "" || current.endsWith("\n") ? "" : "\n";
  fs.writeFileSync(gitignore, `${current}${separator}${BACKUP_PATTERN}\n`);
}

/** Writing through a symbolic link would change a file outside the project (a link planted in someone else's repository). */
function refuseSymbolicLinks(files: string[]): void {
  for (const file of files) {
    try {
      if (fs.lstatSync(file).isSymbolicLink()) throw new Error(`Refusing to write through a symbolic link: ${file}`);
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== "ENOENT") throw err;
    }
  }
}

/** Writes the plan to disk. Returns the files it changed and the backups it made. */
export function applyPlan(plan: FixPlan, options: ApplyOptions = {}): { changed: string[]; backups: string[] } {
  const changed: string[] = [];
  const backups: string[] = [];
  const editsByFile = new Map<string, TextEdit[]>();
  for (const edit of plan.edits) editsByFile.set(edit.file, [...(editsByFile.get(edit.file) ?? []), edit]);

  // compute and check everything first so a failure (an overlap, a symbolic link) changes nothing
  const results = new Map<string, string>();
  for (const [file, edits] of editsByFile) results.set(file, applyEdits(plan.originals[file] ?? readOrEmpty(file), edits));
  refuseSymbolicLinks([...results.keys(), ...plan.writes.map((w) => w.file)]);

  const backup = (file: string): void => {
    if (options.backup && fs.existsSync(file)) {
      fs.copyFileSync(file, `${file}.security-hub.bak`);
      backups.push(`${file}.security-hub.bak`);
    }
  };
  for (const [file, text] of results) {
    backup(file);
    fs.writeFileSync(file, text);
    changed.push(file);
  }
  for (const write of plan.writes) {
    backup(write.file);
    fs.mkdirSync(path.dirname(write.file), { recursive: true });
    // a new .env holds secrets: readable by its owner only (an existing file keeps the permissions it has)
    fs.writeFileSync(write.file, write.content, /^\.env(\.|$)/.test(path.basename(write.file)) ? { mode: 0o600 } : undefined);
    changed.push(write.file);
  }
  if (backups.length > 0 && options.root) ignoreBackups(options.root);
  return { changed, backups };
}
