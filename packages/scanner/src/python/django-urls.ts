import * as fs from "fs";
import * as path from "path";
import { checkBudgetNow } from "../budget";
import { ProjectContext } from "../taint/project";

/**
 * What a Django URL parameter can hold, read from the project's `urls.py` files:
 *
 *   path("users/<int:pk>/", views.user_detail)         pk is a number: nothing of the caller's text reaches the view
 *   path("posts/<slug:slug>/", PostDetail.as_view())   letters, digits, - and _ only
 *   path("files/<name>/", views.download)              one URL segment: any text, but no "/"
 *   path("docs/<path:rest>/", views.docs)              any text
 *   re_path(r"^items/(?P<id>\d+)/$", views.item)       the pattern says
 *
 * The view in a `def view(request, pk)` is otherwise taken to receive any text in every URL parameter.
 */

export type UrlParamKind = "safe" | "segment" | "text";

const RANK: Record<UrlParamKind, number> = { safe: 0, segment: 1, text: 2 };
const SKIP_DIRS = new Set(["node_modules", ".git", "venv", ".venv", "env", "site-packages", "__pycache__", "dist", "build", "migrations", "static", "media"]);
const MAX_FILES = 4000;
const MAX_URL_FILES = 200;
const MAX_BYTES = 512 * 1024;

const CONVERTER_KIND: Record<string, UrlParamKind> = { int: "safe", slug: "safe", uuid: "safe", str: "segment", path: "text" };

/** A regular expression group's pattern: digits or word characters only are safe, "anything but /" is one segment. */
export function regexKind(pattern: string): UrlParamKind {
  const p = pattern.replace(/[+*]$|\{\d+(?:,\d*)?\}$/, "");
  if (/^(?:\\d|\[0-9\]|\\w|\[(?:\\w|\\d|-|_|a-z|A-Z|0-9)+\])$/.test(p)) return "safe";
  if (/^\[\^\/\]$/.test(p) || /^\[\^\/\\?\.?\]$/.test(p)) return "segment";
  return "text";
}

/** The parameters of one route pattern and what each can hold. Undefined for a converter the project registers itself. */
export function routeParams(route: string, isRegex: boolean): Map<string, UrlParamKind> {
  const out = new Map<string, UrlParamKind>();
  if (isRegex) {
    for (const m of route.matchAll(/\(\?P<(\w+)>((?:\\.|\[(?:\\.|[^\]])*\]|[^()\\])*)\)/g)) out.set(m[1] as string, regexKind(m[2] as string));
  } else {
    for (const m of route.matchAll(/<\s*(?:(\w+)\s*:\s*)?(\w+)\s*>/g)) out.set(m[2] as string, m[1] ? (CONVERTER_KIND[m[1]] ?? "text") : "segment");
  }
  return out;
}

const ROUTE_CALL = /\b(re_path|path|url)\(\s*r?(["'])((?:\\.|(?!\2).)*)\2\s*,\s*([A-Za-z_][\w.]*)(\s*\.as_view\b)?/g;

/** View name (a function, or a class-based view's class) -> parameter -> the most the parameter can hold over all its routes. */
export function parseUrlsFile(text: string, into: Map<string, Map<string, UrlParamKind>> = new Map()): Map<string, Map<string, UrlParamKind>> {
  for (const m of text.matchAll(ROUTE_CALL)) {
    const target = (m[4] as string).replace(/\.as_view$/, "");
    if (/^(?:include|admin\.site\.urls)$/.test(target) || target.endsWith(".urls")) continue;
    const view = target.split(".").pop() as string;
    const params = routeParams(m[3] as string, m[1] !== "path");
    const known = into.get(view) ?? new Map<string, UrlParamKind>();
    for (const [name, kind] of params) {
      const before = known.get(name);
      if (!before || RANK[kind] > RANK[before]) known.set(name, kind);
    }
    into.set(view, known);
  }
  return into;
}

const cache = new WeakMap<ProjectContext, Map<string, Map<string, UrlParamKind>>>();

/** The project's URL parameters by view, read once per scan from every `urls.py` under the scanned folder. */
export function djangoUrlParams(context: ProjectContext): Map<string, Map<string, UrlParamKind>> {
  const known = cache.get(context);
  if (known) return known;
  const out = new Map<string, Map<string, UrlParamKind>>();
  cache.set(context, out);
  const stack = [context.root];
  let seen = 0;
  let urlFiles = 0;
  while (stack.length > 0 && seen < MAX_FILES && urlFiles < MAX_URL_FILES) {
    checkBudgetNow();
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
        if (!SKIP_DIRS.has(entry.name)) stack.push(full);
        continue;
      }
      seen++;
      if (!/^urls\.py$|urls?\w*\.py$/.test(entry.name)) continue;
      try {
        if (fs.statSync(full).size > MAX_BYTES) continue;
        const text = fs.readFileSync(full, "utf8");
        if (!/urlpatterns|\bpath\(|\bre_path\(/.test(text)) continue;
        urlFiles++;
        parseUrlsFile(text, out);
      } catch {
        // unreadable: its routes stay unknown, and their views keep the default (any text)
      }
    }
  }
  return out;
}
