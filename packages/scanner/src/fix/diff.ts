import { TextEdit } from "./types";

/** Applies non-overlapping edits (offsets into `original`) to `original`. Throws on overlap. */
export function applyEdits(original: string, edits: TextEdit[]): string {
  const sorted = [...edits].sort((a, b) => a.start - b.start || a.end - b.end);
  let out = "";
  let cursor = 0;
  for (const edit of sorted) {
    if (edit.start < cursor) throw new Error(`Overlapping edits in ${edit.file} at offset ${edit.start}`);
    out += original.slice(cursor, edit.start) + edit.text;
    cursor = edit.end;
  }
  return out + original.slice(cursor);
}

function lineStarts(text: string): number[] {
  const starts = [0];
  for (let i = 0; i < text.length; i++) if (text.charCodeAt(i) === 10) starts.push(i + 1);
  return starts;
}

function lineOf(starts: number[], offset: number): number {
  let low = 0;
  let high = starts.length - 1;
  while (low < high) {
    const mid = (low + high + 1) >> 1;
    if ((starts[mid] as number) <= offset) low = mid;
    else high = mid - 1;
  }
  return low;
}

const CONTEXT = 3;

/**
 * A unified diff of `edits` applied to `original`, one hunk per group of nearby edits. Lines an edit touches are shown
 * whole (removed, then added): the edits are small and local, so this reads like `git diff` without a general diff.
 */
export function unifiedDiff(file: string, original: string, edits: TextEdit[]): string {
  const sorted = [...edits].sort((a, b) => a.start - b.start);
  if (sorted.length === 0) return "";
  const starts = lineStarts(original);
  const lines = original.split("\n");

  // Group edits whose touched lines (plus context) overlap.
  interface Group {
    first: number;
    last: number;
    edits: TextEdit[];
  }
  const groups: Group[] = [];
  for (const edit of sorted) {
    const first = lineOf(starts, edit.start);
    const last = lineOf(starts, Math.max(edit.start, edit.end - 1));
    const previous = groups[groups.length - 1];
    if (previous && first - previous.last <= CONTEXT * 2) {
      previous.last = Math.max(previous.last, last);
      previous.edits.push(edit);
    } else {
      groups.push({ first, last, edits: [edit] });
    }
  }

  const out: string[] = [`--- a/${file}`, `+++ b/${file}`];
  let delta = 0; // new line number - old line number, accumulated over earlier hunks
  for (const group of groups) {
    const from = Math.max(0, group.first - CONTEXT);
    const to = Math.min(lines.length - 1, group.last + CONTEXT);
    const regionStart = starts[group.first] as number;
    const regionEnd = group.last + 1 < starts.length ? (starts[group.last + 1] as number) - 1 : original.length;
    // new text of the touched lines: apply this group's edits to the touched region only
    const localEdits = group.edits.map((e) => ({ ...e, start: e.start - regionStart, end: e.end - regionStart }));
    const touchedOld = original.slice(regionStart, regionEnd);
    const touchedNew = applyEdits(touchedOld, localEdits);
    const oldLines = touchedOld.split("\n");
    const newLines = touchedNew.split("\n");

    const before = lines.slice(from, group.first);
    const after = lines.slice(group.last + 1, to + 1);
    // lines between two edits of the same hunk are unchanged: show them as context, not as removed and added
    const ops = lineDiff(oldLines, newLines);
    const oldCount = before.length + ops.filter((o) => o[0] !== "+").length + after.length;
    const newCount = before.length + ops.filter((o) => o[0] !== "-").length + after.length;
    out.push(`@@ -${from + 1},${oldCount} +${from + 1 + delta},${newCount} @@`);
    for (const l of before) out.push(` ${l}`);
    for (const [kind, l] of ops) out.push(`${kind}${l}`);
    for (const l of after) out.push(` ${l}`);
    delta += newLines.length - oldLines.length;
  }
  return out.join("\n");
}

/** Line diff of two short texts (a region around some edits) by the longest common subsequence. */
function lineDiff(a: string[], b: string[]): Array<[" " | "-" | "+", string]> {
  if (a.length * b.length > 250_000) return [...a.map((l) => ["-", l] as ["-", string]), ...b.map((l) => ["+", l] as ["+", string])];
  const table: number[][] = Array.from({ length: a.length + 1 }, () => new Array<number>(b.length + 1).fill(0));
  for (let i = a.length - 1; i >= 0; i--) {
    for (let j = b.length - 1; j >= 0; j--) {
      table[i]![j] = a[i] === b[j] ? (table[i + 1]![j + 1] as number) + 1 : Math.max(table[i + 1]![j] as number, table[i]![j + 1] as number);
    }
  }
  const ops: Array<[" " | "-" | "+", string]> = [];
  let i = 0;
  let j = 0;
  while (i < a.length && j < b.length) {
    if (a[i] === b[j]) {
      ops.push([" ", a[i] as string]);
      i++;
      j++;
    } else if ((table[i + 1]![j] as number) >= (table[i]![j + 1] as number)) ops.push(["-", a[i++] as string]);
    else ops.push(["+", b[j++] as string]);
  }
  while (i < a.length) ops.push(["-", a[i++] as string]);
  while (j < b.length) ops.push(["+", b[j++] as string]);
  return ops;
}

/** A "new file" diff for a preview. */
export function newFileDiff(file: string, shown: string): string {
  const lines = shown.replace(/\n$/, "").split("\n");
  return [`--- /dev/null`, `+++ b/${file}`, `@@ -0,0 +1,${lines.length} @@`, ...lines.map((l) => `+${l}`)].join("\n");
}

/** A diff for a file that grows at the end (an append to .gitignore / .env.example). */
export function appendDiff(file: string, original: string, shown: string): string {
  const oldLines = original.replace(/\n$/, "").split("\n");
  const newLines = shown.replace(/\n$/, "").split("\n");
  const added = newLines.slice(oldLines.length);
  const context = oldLines.slice(-CONTEXT);
  const startOld = oldLines.length - context.length + 1;
  return [
    `--- a/${file}`,
    `+++ b/${file}`,
    `@@ -${startOld},${context.length} +${startOld},${context.length + added.length} @@`,
    ...context.map((l) => ` ${l}`),
    ...added.map((l) => `+${l}`),
  ].join("\n");
}
