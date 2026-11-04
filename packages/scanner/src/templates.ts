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

function buildIndex(root: string, folderNames: ReadonlySet<string>, extensions: RegExp = EXTENSIONS): Index {
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
      } else if (relativeToTemplates !== undefined && entry.isFile() && extensions.test(entry.name)) {
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

// ---- Node view engines (Express `res.render("profile", { bio })`, Fastify `reply.view`, Koa `ctx.render`) ----

const VIEW_EXTENSIONS = /\.(?:ejs|pug|jade|hbs|handlebars|mustache|njk|nunjucks|swig|html?|twig)$/i;
const VIEW_FOLDERS: ReadonlySet<string> = new Set(["views", "view", "templates", "template"]);
const VIEW_SUFFIX = /\.(?:ejs|pug|jade|hbs|handlebars|mustache|njk|nunjucks|swig|html?|twig)$/i;

export type ViewEngine = "ejs" | "pug" | "hbs" | "nunjucks";

function engineOf(file: string): ViewEngine[] {
  const lower = file.toLowerCase();
  if (lower.endsWith(".ejs")) return ["ejs"];
  if (/\.(?:pug|jade)$/.test(lower)) return ["pug"];
  if (/\.(?:hbs|handlebars|mustache)$/.test(lower)) return ["hbs"];
  if (/\.(?:njk|nunjucks|swig|twig)$/.test(lower)) return ["nunjucks"];
  return ["ejs", "nunjucks"]; // a .html view: either engine can be registered for it
}

/** The view file for `res.render("admin/users")` (or `"users.ejs"`), searched in `views` / `templates` folders. */
export function findViewTemplate(root: string, name: string): string | undefined {
  const cacheKey = `view:${path.resolve(root)}`;
  let index = indexes.get(cacheKey);
  if (!index) {
    index = buildIndex(root, VIEW_FOLDERS, VIEW_EXTENSIONS);
    for (const [key, value] of [...index.byRelative]) {
      const bare = key.replace(VIEW_SUFFIX, "");
      if (!index.byRelative.has(bare)) index.byRelative.set(bare, value);
    }
    indexes.set(cacheKey, index);
  }
  const wanted = name.replace(/^[./\\]+/, "").split("\\").join("/");
  return index.byRelative.get(wanted) ?? index.byRelative.get(wanted.replace(VIEW_SUFFIX, ""));
}

const VIEW_RELATED: Record<ViewEngine, RegExp> = {
  ejs: /\binclude\(\s*["']([^"']+)["']/g,
  pug: /^[ \t]*(?:include|extends)[ \t]+([^\s]+)/gm,
  hbs: /\{\{>\s*([\w./-]+)/g,
  nunjucks: /\{%-?\s*(?:extends|include|embed|import|from)\s+["']([^"']+)["']/g,
};

/**
 * The view and the partials it pulls in by name (`include('partials/nav')`, `include nav`, `{{> nav}}`, `{% include "nav.njk" %}`). A layout that
 * wraps the view implicitly (express-ejs-layouts, express-handlebars' `{{{body}}}`) is NOT followed: its raw `body` is the rendered view.
 */
export function relatedViews(root: string, file: string): string[] {
  const out = [file];
  for (let i = 0; i < out.length && out.length < MAX_RELATED; i++) {
    const current = out[i] as string;
    const text = readTemplate(current);
    if (!text) continue;
    for (const engine of engineOf(current)) {
      const pattern = VIEW_RELATED[engine];
      pattern.lastIndex = 0;
      for (let m = pattern.exec(text); m !== null && out.length < MAX_RELATED; m = pattern.exec(text)) {
        const name = m[1] as string;
        const sibling = [name, `${name}.ejs`, `${name}.pug`, `${name}.hbs`, `${name}.njk`].map((n) => path.resolve(path.dirname(current), n)).find((candidate) => fs.existsSync(candidate) && fs.statSync(candidate).isFile());
        const found = sibling ?? findViewTemplate(root, name) ?? findViewTemplate(root, `partials/${name}`);
        if (found && !out.includes(found)) out.push(found);
      }
    }
  }
  return out;
}

// An expression that escapes (or sanitises) on its way out: the raw tag only carries markup that is already safe.
const VIEW_ESCAPED = /(?:escape|encode|sanitiz|purif|clean|strip|xss|DOMPurify|sanitizeHtml)\w*\s*\(/i;

/**
 * The names a template gives to what it was handed under `key`: `{% for post in posts %}` -> post, `posts.forEach(function (post) {` -> post,
 * `each post in posts` -> post, `{% set p = posts[0] %}` -> p. A list handed in as `posts` is printed through its loop variable, so a raw print of
 * `post.body` is a raw print of `posts`. Two rounds, for a loop inside a loop.
 */
export function keyAliases(text: string, key: string, kind: "jinja" | "ejs" | "pug"): string[] {
  const names = new Set<string>([key]);
  for (let round = 0; round < 2; round++) {
    for (const known of [...names]) {
      const k = escapeRegex(known);
      const root = `(?<![\\w$.])${k}\\b`;
      const found: string[] = [];
      if (kind === "jinja") {
        for (const m of text.matchAll(new RegExp(`\\{%-?\\s*for\\s+(\\w+)(?:\\s*,\\s*(\\w+))?\\s+in\\s+[^%]*?${root}`, "g"))) found.push(m[1] as string, m[2] as string);
        for (const m of text.matchAll(new RegExp(`\\{%-?\\s*set\\s+(\\w+)\\s*=\\s*[^%]*?${root}`, "g"))) found.push(m[1] as string);
      } else if (kind === "ejs") {
        for (const m of text.matchAll(new RegExp(`${root}[^%]*?\\.(?:forEach|map|filter|some|every)\\(\\s*(?:function\\s*\\(\\s*|\\(\\s*)?(\\w+)`, "g"))) found.push(m[1] as string);
        for (const m of text.matchAll(new RegExp(`for\\s*\\(\\s*(?:const|let|var)\\s+(\\w+)\\s+(?:of|in)\\s+${k}\\b`, "g"))) found.push(m[1] as string);
        for (const m of text.matchAll(new RegExp(`(?:const|let|var)\\s+(\\w+)\\s*=\\s*[^;%]*?${root}`, "g"))) found.push(m[1] as string);
      } else {
        for (const m of text.matchAll(new RegExp(`^[ \\t]*(?:each|for)\\s+(\\w+)(?:\\s*,\\s*\\w+)?\\s+in\\s+${k}\\b`, "gm"))) found.push(m[1] as string);
      }
      for (const name of found) if (name && !/^(?:in|of|key|index|i|_)$/.test(name)) names.add(name);
    }
  }
  return [...names];
}

function mentionsAny(expression: string, names: string[]): boolean {
  return names.some((name) => mentions(expression, name));
}

function mentions(expression: string, key: string): boolean {
  return new RegExp(`(?<![\\w$.])(?:locals\\.|this\\.)?${escapeRegex(key)}\\b`).test(expression);
}

function ejsUnsafeUseIn(file: string, text: string, key: string): UnsafeUse | undefined {
  const names = keyAliases(text, key, "ejs");
  // <%- value %>: EJS prints it as it is (<%= %> escapes). `<%- include(...) %>` pulls in a partial.
  const raw = /<%-\s*([\s\S]*?)\s*-?%>/g;
  for (let m = raw.exec(text); m !== null; m = raw.exec(text)) {
    const expression = m[1] ?? "";
    if (/^include\s*\(/.test(expression) || VIEW_ESCAPED.test(expression) || !mentionsAny(expression, names)) continue;
    return { file, line: lineOf(text, m.index), how: `<%- ${expression.trim().slice(0, 40)} %>` };
  }
  return undefined;
}

function pugUnsafeUseIn(file: string, text: string, key: string): UnsafeUse | undefined {
  const names = keyAliases(text, key, "pug");
  // !{value} and p!= value: Pug escapes #{value} and p= value, and prints these as they are
  const interpolation = /!\{([^}]*)\}/g;
  for (let m = interpolation.exec(text); m !== null; m = interpolation.exec(text)) {
    const expression = m[1] ?? "";
    if (!VIEW_ESCAPED.test(expression) && mentionsAny(expression, names)) return { file, line: lineOf(text, m.index), how: `!{${expression.trim().slice(0, 40)}}` };
  }
  const buffered = /^[^\S\n]*[\w.#-]*(?:\([^)\n]*\))?!=[^\S\n]*(.+)$/gm;
  for (let m = buffered.exec(text); m !== null; m = buffered.exec(text)) {
    const expression = m[1] ?? "";
    if (!VIEW_ESCAPED.test(expression) && mentionsAny(expression, names)) return { file, line: lineOf(text, m.index), how: `!= ${expression.trim().slice(0, 40)}` };
  }
  return undefined;
}

function hbsUnsafeUseIn(file: string, text: string, key: string): UnsafeUse | undefined {
  for (const block of text.matchAll(/\{\{#each\s+([^}]+)\}\}([\s\S]*?)\{\{\/each\}\}/g)) {
    if (!mentions(block[1] ?? "", key)) continue;
    const inner = /\{\{\{([^}]+)\}\}\}|\{\{&\s*([^}]+)\}\}/.exec(block[2] ?? "");
    if (inner && !VIEW_ESCAPED.test(inner[1] ?? inner[2] ?? "")) return { file, line: lineOf(text, (block.index ?? 0) + (block[0].indexOf(inner[0]))), how: `{{#each ${key}}} ... ${inner[0].slice(0, 30)}` };
  }
  // {{{value}}} and {{& value}}: Handlebars / Mustache print them as they are ({{value}} escapes)
  const raw = /\{\{\{([^}]+)\}\}\}|\{\{&\s*([^}]+)\}\}/g;
  for (let m = raw.exec(text); m !== null; m = raw.exec(text)) {
    const expression = (m[1] ?? m[2] ?? "").trim();
    if (!VIEW_ESCAPED.test(expression) && mentions(expression, key)) return { file, line: lineOf(text, m.index), how: m[0].slice(0, 40) };
  }
  return undefined;
}

// `swig.setDefaults({ autoescape: false })`, `nunjucks.configure("views", { autoescape: false })`, `new nunjucks.Environment(loader, { autoescape: false })`
const AUTOESCAPE_OFF = /(?:setDefaults|configure|Environment)\s*\([^;]*?autoescape\s*:\s*false/;
const SCRIPT_FILE = /\.(?:[cm]?js|ts)$/;
const SKIP_PROJECT_DIRS = new Set(["node_modules", ".git", "dist", "build", "coverage", ".next", "vendor", "public", "static"]);
const autoescapeOffRoots = new Map<string, boolean>();

/** Does any server file of the project switch the template engine's escaping off? A text search over at most 1500 script files. */
export function engineAutoescapeOff(root: string): boolean {
  const key = path.resolve(root);
  const known = autoescapeOffRoots.get(key);
  if (known !== undefined) return known;
  let found = false;
  let seen = 0;
  const stack = [key];
  while (stack.length > 0 && !found && seen < 1500) {
    const dir = stack.pop() as string;
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true }) as fs.Dirent[];
    } catch {
      continue;
    }
    for (const entry of entries) {
      if (entry.name.startsWith(".")) continue;
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (!SKIP_PROJECT_DIRS.has(entry.name)) stack.push(full);
      } else if (entry.isFile() && SCRIPT_FILE.test(entry.name)) {
        seen++;
        const text = readTemplate(full);
        if (text && AUTOESCAPE_OFF.test(text)) {
          found = true;
          break;
        }
      }
    }
  }
  autoescapeOffRoots.set(key, found);
  return found;
}

/** `{{ key }}` in a Nunjucks / Swig / Twig view when the engine does not escape: unless the print passes through `| escape` / `| e`. */
function plainPrintUseIn(file: string, text: string, key: string): UnsafeUse | undefined {
  const names = keyAliases(text, key, "jinja");
  const print = /\{\{-?([^}]*)\}\}/g;
  for (let m = print.exec(text); m !== null; m = print.exec(text)) {
    const expression = m[1] ?? "";
    if (mentionsAny(expression, names) && !/\|\s*(?:e|escape|forceescape|urlencode|striptags|dump)\b/.test(expression)) {
      return { file, line: lineOf(text, m.index), how: `{{ ${expression.trim().slice(0, 40)} }} with autoescape turned off` };
    }
  }
  return undefined;
}

/** How a Node view (and the partials it includes) prints `key` unescaped, if it does. */
export function viewUnsafeUse(file: string, key: string, root: string): UnsafeUse | undefined {
  const escapingOff = engineAutoescapeOff(root);
  for (const each of relatedViews(root, file)) {
    const text = readTemplate(each);
    if (!text) continue;
    for (const engine of engineOf(each)) {
      const use =
        engine === "ejs"
          ? ejsUnsafeUseIn(each, text, key)
          : engine === "pug"
            ? pugUnsafeUseIn(each, text, key)
            : engine === "hbs"
              ? hbsUnsafeUseIn(each, text, key)
              : (escapingOff ? plainPrintUseIn(each, text, key) : undefined) ?? jinjaUnsafeUseIn(each, key);
      if (use) return use;
    }
  }
  return undefined;
}

/** Forget what was read (a new scan of the same folder must see edited templates). */
export function forgetTemplates(): void {
  indexes.clear();
  autoescapeOffRoots.clear();
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

const MAX_RELATED = 12;
// `{% extends "base.html" %}`, `{% include "parts/row.html" %}`, `{% embed %}` (Twig): templates that print with the same variables
const JINJA_RELATED = /\{%-?\s*(?:extends|include|embed)\s+["']([^"']+)["']/g;
// `@extends('layouts.app')`, `@include('parts.row')`, `@includeIf('x')`, `@component('x')`
const BLADE_RELATED = /@(?:extends|include|includeIf|includeFirst|component)\s*\(\s*\[?\s*["']([^"']+)["']/g;

/**
 * The template and the ones it pulls in (its parent layout, its includes, theirs): a value handed to `page.html` is printed by
 * `base.html` too when page.html extends it. Up to 12 files.
 */
export function relatedTemplates(root: string, file: string, kind: "jinja" | "blade"): string[] {
  const out = [file];
  for (let i = 0; i < out.length && out.length < MAX_RELATED; i++) {
    const text = readTemplate(out[i] as string);
    if (!text) continue;
    const pattern = kind === "blade" ? BLADE_RELATED : JINJA_RELATED;
    pattern.lastIndex = 0;
    for (let m = pattern.exec(text); m !== null && out.length < MAX_RELATED; m = pattern.exec(text)) {
      const found = findTemplate(root, m[1] as string, kind);
      if (found && !out.includes(found)) out.push(found);
    }
  }
  return out;
}

export interface UnsafeUse {
  file: string;
  line: number;
  how: string;
}

/** `{{ key|safe }}` (or `|raw`, or inside `{% autoescape false %}`) in the template or in a template it extends or includes. */
export function jinjaUnsafeUse(file: string, key: string, root?: string): UnsafeUse | undefined {
  for (const each of root ? relatedTemplates(root, file, "jinja") : [file]) {
    const use = jinjaUnsafeUseIn(each, key);
    if (use) return use;
  }
  return undefined;
}

/** `{{ key|safe }}`, `{{ key.attr | safe }}`, `{{ key|raw }}` (Twig), or `{{ key }}` inside `{% autoescape false %}`. */
function jinjaUnsafeUseIn(file: string, key: string): UnsafeUse | undefined {
  const text = readTemplate(file);
  if (!text) return undefined;
  for (const alias of keyAliases(text, key, "jinja")) {
    const name = escapeRegex(alias);
    const filter = new RegExp(`\\{\\{-?[^}]*(?<![\\w.])${name}\\b[^}]*\\|\\s*(?:safe|raw)\\b`);
    const direct = filter.exec(text);
    // `{{ x|e|safe }}` / `{{ x|escape|safe }}` / `{{ x|striptags|safe }}`: escaped first, then marked safe
    if (direct && !/\|\s*(?:e|escape|striptags|forceescape|urlencode)\b[^}]*\|\s*(?:safe|raw)\b/.test(direct[0])) return { file, line: lineOf(text, direct.index), how: `{{ ${alias}|safe }}` };
    const off = /\{%-?\s*autoescape\s+(?:false|off)\s*-?%\}([\s\S]*?)\{%-?\s*endautoescape/g;
    for (let m = off.exec(text); m !== null; m = off.exec(text)) {
      const inside = new RegExp(`\\{\\{-?\\s*(?<![\\w.])${name}\\b`).exec(m[1] ?? "");
      if (inside) return { file, line: lineOf(text, m.index + (inside.index ?? 0)), how: `{{ ${alias} }} inside autoescape off` };
    }
  }
  return undefined;
}

/** `{!! $key !!}` in the view or in a view it extends or includes. */
export function bladeUnsafeUse(file: string, key: string, root?: string): UnsafeUse | undefined {
  for (const each of root ? relatedTemplates(root, file, "blade") : [file]) {
    const use = bladeUnsafeUseIn(each, key);
    if (use) return use;
  }
  return undefined;
}

/** `{!! $key !!}` and `{!! $key->name !!}`, which Blade prints raw. */
function bladeUnsafeUseIn(file: string, key: string): UnsafeUse | undefined {
  const text = readTemplate(file);
  if (!text) return undefined;
  const names = bladeAliases(text, key);
  const expression = new RegExp(`\\{!!([^}]*\\$(${names.map(escapeRegex).join("|")})\\b[^}]*)!!\\}`, "g");
  for (let m = expression.exec(text); m !== null; m = expression.exec(text)) {
    // {!! e($x) !!}, {!! nl2br(e(strip_tags($x))) !!}: escaped on the way out; the raw tag only carries the markup the template wrote
    if (BLADE_ESCAPED.test(m[1] ?? "")) continue;
    return { file, line: lineOf(text, m.index), how: `{!! $${m[2]} !!}` };
  }
  return undefined;
}

/** `@foreach ($posts as $post)` / `@forelse ($posts as $id => $post)`: the loop variable holds what the handed-in list holds. */
function bladeAliases(text: string, key: string): string[] {
  const names = new Set<string>([key]);
  for (let round = 0; round < 2; round++) {
    for (const known of [...names]) {
      const loop = new RegExp(`@(?:foreach|forelse)\\s*\\(\\s*\\$${escapeRegex(known)}\\b[^)]*?\\s+as\\s+(?:\\$\\w+\\s*=>\\s*)?\\$(\\w+)`, "g");
      for (const m of text.matchAll(loop)) if (m[1]) names.add(m[1]);
    }
  }
  return [...names];
}

const BLADE_ESCAPED = /(?:^|[^\w$>:])(?:e|htmlspecialchars|htmlentities|strip_tags|json_encode|Purifier::clean|clean|Str::of|nl2br\(\s*e)\s*\(/;
