import * as fs from "fs";
import * as path from "path";
import { FileCache } from "../file-cache";
import { applyInlineSuppressions } from "../suppress";
import { Finding, ScanResult } from "../types";
import { analyzeFirebaseRules, analyzeRealtimeDatabaseRules } from "./firebase-rules";
import { SqlFile, analyzeSupabaseSql } from "./supabase-sql";

/**
 * Finds and checks the files that are not source code but decide who can read your data:
 * Supabase SQL migrations, Firestore / Cloud Storage rules, Realtime Database rules.
 */

const MAX_FILE_BYTES = 2 * 1024 * 1024;
const SUPABASE_SQL_MARKER = /\bauth\.(uid|jwt|role)\s*\(|\bto\s+(anon|authenticated)\b|storage\.(buckets|objects)|supabase_functions/i;

const supabaseDependencyCache = new FileCache<boolean>();

function packageHasSupabase(dir: string): boolean | undefined {
  const file = path.join(dir, "package.json");
  const cached = supabaseDependencyCache.get(file);
  if (cached !== undefined) return cached;
  if (!fs.existsSync(file)) return undefined;
  let result = false;
  try {
    const pkg = JSON.parse(fs.readFileSync(file, "utf8"));
    result = Object.keys({ ...pkg.dependencies, ...pkg.devDependencies }).some((d) => d === "supabase" || d.startsWith("@supabase/"));
  } catch {
    result = false;
  }
  supabaseDependencyCache.set(file, result);
  return result;
}

/** Does a package.json between `file` and `root` (inclusive) depend on Supabase? */
function projectUsesSupabase(file: string, root: string): boolean {
  let dir = path.dirname(file);
  for (let depth = 0; depth < 12; depth++) {
    if (packageHasSupabase(dir)) return true;
    if (dir === root) break;
    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return false;
}

/** The nearest ancestor folder called `supabase` (the Supabase CLI project root), or `root`. */
function supabaseRootOf(file: string, root: string): string {
  let dir = path.dirname(file);
  while (dir.length >= root.length) {
    if (path.basename(dir) === "supabase") return dir;
    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return root;
}

/** `[api] schemas = ["public", "graphql_public"]` from supabase/config.toml. */
function exposedSchemas(supabaseRoot: string): string[] | undefined {
  try {
    const toml = fs.readFileSync(path.join(supabaseRoot, "config.toml"), "utf8");
    const api = /^\[api\][\s\S]*?(?=^\[|$(?![\s\S]))/m.exec(toml)?.[0] ?? "";
    const list = /^\s*schemas\s*=\s*\[([^\]]*)\]/m.exec(api)?.[1];
    return list ? [...list.matchAll(/["']([^"']+)["']/g)].map((m) => m[1] as string) : undefined;
  } catch {
    return undefined;
  }
}

interface Candidates {
  sql: string[];
  rules: string[];
  rtdb: string[];
}

function collect(root: string, skipDirs: Set<string>, isIgnored: (relative: string) => boolean): Candidates {
  const found: Candidates = { sql: [], rules: [], rtdb: [] };
  const stack = [root];
  while (stack.length > 0) {
    const current = stack.pop() as string;
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(current, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const entry of entries) {
      const full = path.join(current, entry.name);
      if (isIgnored(path.relative(root, full).split(path.sep).join("/"))) continue;
      if (entry.isDirectory()) {
        if (!skipDirs.has(entry.name) && !entry.name.startsWith(".")) stack.push(full);
      } else if (entry.isFile()) {
        if (/\.sql$/i.test(entry.name)) found.sql.push(full);
        else if (/\.rules$/i.test(entry.name)) found.rules.push(full);
        else if (/\.rules\.json$/i.test(entry.name) || entry.name === "database.rules.json") found.rtdb.push(full);
      }
    }
  }
  return found;
}

function read(file: string): string | undefined {
  try {
    if (fs.statSync(file).size > MAX_FILE_BYTES) return undefined;
    return fs.readFileSync(file, "utf8");
  } catch {
    return undefined;
  }
}

export function scanBackendConfigs(root: string, skipDirs: Set<string>, isIgnored: (relative: string) => boolean): ScanResult[] {
  const candidates = collect(root, skipDirs, isIgnored);
  const results: ScanResult[] = [];
  const texts = new Map<string, string>();
  const findingsByFile = new Map<string, Finding[]>();
  const addFindings = (file: string, findings: Finding[]): void => {
    if (findings.length > 0) findingsByFile.set(file, [...(findingsByFile.get(file) ?? []), ...findings]);
  };

  // Supabase: SQL files grouped by Supabase project, analysed as one migration timeline each.
  const groups = new Map<string, SqlFile[]>();
  for (const file of candidates.sql) {
    const text = read(file);
    if (text === undefined) continue;
    const underSupabase = file.split(path.sep).includes("supabase");
    if (!underSupabase && !projectUsesSupabase(file, root) && !SUPABASE_SQL_MARKER.test(text)) continue;
    texts.set(file, text);
    const key = supabaseRootOf(file, root);
    groups.set(key, [...(groups.get(key) ?? []), { file, text }]);
  }
  for (const [supabaseRoot, files] of groups) {
    for (const [file, findings] of analyzeSupabaseSql(files, { exposedSchemas: exposedSchemas(supabaseRoot) })) addFindings(file, findings);
  }

  // Firebase: Firestore / Storage rules and Realtime Database rules.
  for (const file of candidates.rules) {
    const text = read(file);
    if (text === undefined) continue;
    const kind = /service\s+firebase\.storage/.test(text) ? "storage" : /service\s+cloud\.firestore/.test(text) ? "firestore" : undefined;
    if (!kind) continue;
    texts.set(file, text);
    addFindings(file, analyzeFirebaseRules(text, file, kind));
  }
  for (const file of candidates.rtdb) {
    const text = read(file);
    if (text === undefined) continue;
    texts.set(file, text);
    addFindings(file, analyzeRealtimeDatabaseRules(text, file));
  }

  for (const file of [...texts.keys()].sort()) {
    const { kept, suppressed } = applyInlineSuppressions(findingsByFile.get(file) ?? [], texts.get(file) ?? "");
    const result: ScanResult = { file, findings: kept };
    if (suppressed > 0) result.suppressed = suppressed;
    results.push(result);
  }
  return results;
}
