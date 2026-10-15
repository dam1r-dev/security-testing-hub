// A read-only, in-memory `fs` for the browser build. The page cannot walk a disk, so the files the user dropped are
// mounted here under a virtual root and the scanner reads them through the same calls it uses on a real folder
// (scanPath, the .env / Supabase / Firebase / exposed-files checks). One code path, so the web page and the command
// line cannot drift apart. Only what the scanner calls is implemented.
import * as path from "./path";

export interface MountedFile {
  /** Path relative to the root of the dropped folder, with forward slashes. */
  path: string;
  size: number;
  /** The content, when the file is text the scanner may read; files that are only listed (images, archives) have none. */
  text?: string;
}

interface Entry {
  size: number;
  text: string;
  mtimeMs: number;
}

let files = new Map<string, Entry>();
let directories = new Map<string, Set<string>>();
const openFiles = new Map<number, Uint8Array>();
let nextDescriptor = 3;
// Caches inside the scanner (which package.json lists which libraries) are keyed by path and checked by modification time. Every
// mount is a different project at the same virtual paths, so every mount gets its own time, or the second project would see the
// first one's cached answers.
let generation = 0;

function fail(code: string, syscall: string, target: string): never {
  const error = new Error(`${code}: no such file or directory, ${syscall} '${target}'`) as Error & { code: string };
  error.code = code;
  throw error;
}

/** Replaces whatever was mounted before. `root` is the absolute virtual path of the dropped folder. */
export function mount(root: string, list: MountedFile[]): void {
  files = new Map();
  directories = new Map();
  generation += 1;
  const addChild = (dir: string, name: string): void => {
    let children = directories.get(dir);
    if (!children) directories.set(dir, (children = new Set()));
    children.add(name);
  };
  directories.set(root, new Set());
  for (const file of list) {
    const absolute = path.join(root, file.path);
    files.set(absolute, { size: file.size, text: file.text ?? "", mtimeMs: generation });
    let current = absolute;
    while (current !== root && current !== "/") {
      const parent = path.dirname(current);
      addChild(parent, path.basename(current));
      current = parent;
    }
  }
}

export function unmount(): void {
  files = new Map();
  directories = new Map();
}

function entryFor(p: string): Entry | undefined {
  return files.get(path.resolve(p));
}

export class Dirent {
  constructor(
    public name: string,
    private readonly kind: "file" | "directory",
  ) {}
  isFile(): boolean {
    return this.kind === "file";
  }
  isDirectory(): boolean {
    return this.kind === "directory";
  }
  isSymbolicLink(): boolean {
    return false; // a dropped folder never carries links: the browser does not offer them
  }
}

export function existsSync(p: string): boolean {
  const resolved = path.resolve(p);
  return files.has(resolved) || directories.has(resolved);
}

export function statSync(p: string): { size: number; mtimeMs: number; isFile(): boolean; isDirectory(): boolean } {
  const resolved = path.resolve(p);
  const file = files.get(resolved);
  if (file) return { size: file.size, mtimeMs: file.mtimeMs, isFile: () => true, isDirectory: () => false };
  if (directories.has(resolved)) return { size: 0, mtimeMs: 0, isFile: () => false, isDirectory: () => true };
  return fail("ENOENT", "stat", p);
}

export function readFileSync(p: string, encoding?: unknown): string | Uint8Array {
  const file = entryFor(p);
  if (!file) return fail("ENOENT", "open", p);
  return encoding ? file.text : new TextEncoder().encode(file.text);
}

export function readdirSync(p: string, options?: { withFileTypes?: boolean }): string[] | Dirent[] {
  const resolved = path.resolve(p);
  const children = directories.get(resolved);
  if (!children) return fail("ENOENT", "scandir", p);
  const names = [...children].sort();
  if (!options?.withFileTypes) return names;
  return names.map((name) => new Dirent(name, directories.has(path.join(resolved, name)) ? "directory" : "file"));
}

export function openSync(p: string): number {
  const file = entryFor(p);
  if (!file) return fail("ENOENT", "open", p);
  const descriptor = nextDescriptor++;
  openFiles.set(descriptor, new TextEncoder().encode(file.text));
  return descriptor;
}

export function readSync(descriptor: number, buffer: Uint8Array, offset: number, length: number, position: number | null): number {
  const bytes = openFiles.get(descriptor);
  if (!bytes) return 0;
  const from = position ?? 0;
  const chunk = bytes.subarray(from, from + length);
  buffer.set(chunk, offset);
  return chunk.length;
}

export function closeSync(descriptor: number): void {
  openFiles.delete(descriptor);
}

function realpath(p: string): string {
  return path.resolve(p);
}
realpath.native = realpath;
export const realpathSync = realpath;
