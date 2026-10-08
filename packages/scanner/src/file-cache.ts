import * as fs from "fs";

/**
 * A per-file cache that notices when the file changes. The scanner can live inside a long-running process
 * (`security-hub ui` rescans the same project again and again), and project facts such as "which auth library
 * does package.json list" must follow edits instead of being frozen at the first scan.
 */
export class FileCache<T> {
  private readonly entries = new Map<string, { mtimeMs: number; value: T }>();

  get(file: string): T | undefined {
    const entry = this.entries.get(file);
    if (!entry) return undefined;
    try {
      return fs.statSync(file).mtimeMs === entry.mtimeMs ? entry.value : undefined;
    } catch {
      return undefined;
    }
  }

  set(file: string, value: T): void {
    try {
      this.entries.set(file, { mtimeMs: fs.statSync(file).mtimeMs, value });
    } catch {
      // an unreadable file is simply not cached
    }
  }
}
