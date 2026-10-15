// A POSIX `path` for the browser build of the scanner (the page has no Node). Behaves like Node's `path.posix` for the
// functions the scanner uses; tests/web-shims.test.ts compares it with the real thing on a long list of inputs.

export const sep = "/";

function segments(parts: string[], absolute: boolean): string[] {
  const out: string[] = [];
  for (const part of parts) {
    if (part === "" || part === ".") continue;
    if (part === "..") {
      if (out.length > 0 && out[out.length - 1] !== "..") out.pop();
      else if (!absolute) out.push("..");
    } else {
      out.push(part);
    }
  }
  return out;
}

export function isAbsolute(p: string): boolean {
  return p.startsWith("/");
}

export function normalize(p: string): string {
  if (p === "") return ".";
  const absolute = isAbsolute(p);
  let joined = segments(p.split("/"), absolute).join("/");
  if (joined === "" && !absolute) joined = ".";
  if (joined !== "" && p.endsWith("/")) joined += "/";
  return (absolute ? "/" : "") + joined;
}

export function join(...parts: string[]): string {
  const joined = parts.filter((part) => part !== "").join("/");
  return joined === "" ? "." : normalize(joined);
}

/** The working directory of the page is the root of the virtual file system. */
export function resolve(...parts: string[]): string {
  let resolved = "";
  for (let i = parts.length - 1; i >= 0; i--) {
    const part = parts[i] as string;
    if (part === "") continue;
    resolved = resolved === "" ? part : `${part}/${resolved}`;
    if (isAbsolute(part)) break;
  }
  return "/" + segments(resolved.split("/"), true).join("/");
}

export function dirname(p: string): string {
  if (p === "") return ".";
  let end = p.length;
  while (end > 1 && p[end - 1] === "/") end--; // trailing slashes do not count
  const trimmed = p.slice(0, end);
  const slash = trimmed.lastIndexOf("/");
  if (slash === -1) return ".";
  if (slash === 0) return "/";
  return trimmed.slice(0, slash); // like Node: a doubled slash inside the path stays (`/a//b` -> `/a/`)
}

export function basename(p: string, ext?: string): string {
  let end = p.length;
  while (end > 0 && p[end - 1] === "/") end--;
  const trimmed = p.slice(0, end);
  const name = trimmed.slice(trimmed.lastIndexOf("/") + 1);
  if (ext !== undefined && ext !== "" && name !== ext && name.endsWith(ext)) return name.slice(0, name.length - ext.length);
  return name;
}

export function extname(p: string): string {
  const name = basename(p);
  const dot = name.lastIndexOf(".");
  if (dot <= 0 || name === "..") return "";
  return name.slice(dot);
}

export function relative(from: string, to: string): string {
  const a = resolve(from).split("/").filter(Boolean);
  const b = resolve(to).split("/").filter(Boolean);
  let common = 0;
  while (common < a.length && common < b.length && a[common] === b[common]) common++;
  return [...a.slice(common).map(() => ".."), ...b.slice(common)].join("/");
}

export const posix = { sep, isAbsolute, normalize, join, resolve, dirname, basename, extname, relative };
export default posix;
