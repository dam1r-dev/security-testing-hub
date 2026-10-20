import * as fs from "fs";
import * as path from "path";

/**
 * Template files, read only to answer one question: does this template print the variable WITHOUT escaping it? A view that hands
 * request data to `render_template("page.html", name=value)` is safe when the template says `{{ name }}` (Jinja and Django escape by
 * default) and a cross-site-scripting hole when it says `{{ name|safe }}`, or `{!! $name !!}` in Blade. The data-flow analyzers
 * (python/analyzer.ts, php/analyzer.ts) know the value is the caller's; this file knows how the template prints it.
 */

const SKIP_DIRS = new Set(["node_modules", ".git", "venv", ".venv", "site-packages", "vendor", "dist", "build", "__pycache__", "storage"]);
const MAX_FILES = 3000;
const MAX_TEMPLATE_BYTES = 512 * 1024;
const EXTENSIONS = /\.(?:html?|jinja2?|j2|txt|xml|svg|blade\.php|twig)$/i;

interface Index {
  /** Path relative to a `templates` / `views` folder, with forward slashes -> the file. */
  byRelative: Map<string, string>;
}

const indexes = new Map<string, Index>();

function buildIndex(root: string, folderNames: ReadonlySet<string>): Index {
  const byRelative = new Map<string, string>();
  const stack: Array<{ dir: string; relativeToTemplates?: string }> = [{ dir: root }];
  let seen = 0;
  while (stack.length > 0 && seen < MAX_FILES) {
    const { dir, relativeToTemplates } = stack.pop() as { dir: string; relativeToTemplates?: string };
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true }) as fs.Dirent[];
    } catch {
      continue;
    }
    for (const entry of entries) {
      if (entry.name.startsWith(".") && entry.name !== ".") continue;
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (SKIP_DIRS.has(entry.name)) continue;
        if (relativeToTemplates !== undefined) stack.push({ dir: full, relativeToTemplates: `${relativeToTemplates}${entry.name}/` });
        else stack.push({ dir: full, relativeToTemplates: folderNames.has(entry.name) ? "" : undefined });
      } else if (relativeToTemplates !== undefined && entry.isFile() && EXTENSIONS.test(entry.name)) {
        seen++;
        const key = `${relativeToTemplates}${entry.name}`;
        if (!byRelative.has(key)) byRelative.set(key, full);
      }
    }
  }
  return { byRelative };
}

/** The template file for a name such as `users/list.html` (Jinja, Django) or `users.list` (Blade), searched in the project's template folders. */
export function findTemplate(root: string, name: string, kind: "jinja" | "blade"): string | undefined {
  const cacheKey = `${kind}:${path.resolve(root)}`;
  let index = indexes.get(cacheKey);
  if (!index) {
    index = buildIndex(root, kind === "blade" ? new Set(["views"]) : new Set(["templates"]));
    indexes.set(cacheKey, index);
  }
  const wanted = kind === "blade" ? `${name.replace(/\./g, "/")}.blade.php` : name.replace(/^\/+/, "");
  return index.byRelative.get(wanted);
}

/** Forget what was read (a new scan of the same folder must see edited templates). */
export function forgetTemplates(): void {
  indexes.clear();
}

function readTemplate(file: string): string | undefined {
  try {
    if (fs.statSync(file).size > MAX_TEMPLATE_BYTES) return undefined;
    return fs.readFileSync(file, "utf8");
  } catch {
    return undefined;
  }
}

function lineOf(text: string, index: number): number {
  let line = 1;
  for (let i = 0; i < index && i < text.length; i++) if (text.charCodeAt(i) === 10) line++;
  return line;
}

function escapeRegex(text: string): string {
  return text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

export interface UnsafeUse {
  file: string;
  line: number;
  how: string;
}

/** `{{ key|safe }}`, `{{ key.attr | safe }}`, `{{ key|raw }}` (Twig), or `{{ key }}` inside `{% autoescape false %}`. */
export function jinjaUnsafeUse(file: string, key: string): UnsafeUse | undefined {
  const text = readTemplate(file);
  if (!text) return undefined;
  const name = escapeRegex(key);
  const filter = new RegExp(`\\{\\{-?[^}]*(?<![\\w.])${name}\\b[^}]*\\|\\s*(?:safe|raw)\\b`);
  const direct = filter.exec(text);
  // `{{ x|e|safe }}` / `{{ x|escape|safe }}` / `{{ x|striptags|safe }}`: escaped first, then marked safe
  if (direct && !/\|\s*(?:e|escape|striptags|forceescape|urlencode)\b[^}]*\|\s*(?:safe|raw)\b/.test(direct[0])) return { file, line: lineOf(text, direct.index), how: `{{ ${key}|safe }}` };
  const off = /\{%-?\s*autoescape\s+(?:false|off)\s*-?%\}([\s\S]*?)\{%-?\s*endautoescape/g;
  for (let m = off.exec(text); m !== null; m = off.exec(text)) {
    const inside = new RegExp(`\\{\\{-?\\s*(?<![\\w.])${name}\\b`).exec(m[1] ?? "");
    if (inside) return { file, line: lineOf(text, m.index + (inside.index ?? 0)), how: `{{ ${key} }} inside autoescape off` };
  }
  return undefined;
}

/** `{!! $key !!}` and `{!! $key->name !!}`, which Blade prints raw. */
export function bladeUnsafeUse(file: string, key: string): UnsafeUse | undefined {
  const text = readTemplate(file);
  if (!text) return undefined;
  const expression = new RegExp(`\\{!!([^}]*\\$${escapeRegex(key)}\\b[^}]*)!!\\}`, "g");
  for (let m = expression.exec(text); m !== null; m = expression.exec(text)) {
    // {!! e($x) !!}, {!! nl2br(e(strip_tags($x))) !!}: escaped on the way out; the raw tag only carries the markup the template wrote
    if (BLADE_ESCAPED.test(m[1] ?? "")) continue;
    return { file, line: lineOf(text, m.index), how: `{!! $${key} !!}` };
  }
  return undefined;
}

const BLADE_ESCAPED = /(?:^|[^\w$>:])(?:e|htmlspecialchars|htmlentities|strip_tags|json_encode|Purifier::clean|clean|Str::of|nl2br\(\s*e)\s*\(/;
