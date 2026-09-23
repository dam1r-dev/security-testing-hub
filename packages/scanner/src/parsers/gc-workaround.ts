import * as v8 from "v8";
import { runInNewContext } from "vm";

/**
 * Works around a real, reproducible bug in node-tree-sitter (0.21.x): when
 * scanning many files back-to-back in one process, parsing/analyzing a file
 * that isn't the first one can silently return a subtly wrong tree for some
 * files (taint that should be found isn't) — confirmed independent of file
 * size/content, confirmed to go away whenever a full GC happens to run at
 * the right moment, and confirmed fixed deterministically by forcing a full
 * GC pass between files. This has nothing to do with our own scanning logic
 * (reproduces identically parsing+analyzing a single file in complete
 * isolation vs. as the 4th of 6 files scanned in one process).
 *
 * Forcing a real V8 GC normally requires launching node with --expose-gc,
 * which we can't require of every consumer of this library/CLI. This grabs
 * a callable gc() the same way some profiling tools do: briefly flip on the
 * flag, capture the global it exposes, flip it back off.
 */
function createForcedGc(): () => void {
  try {
    v8.setFlagsFromString("--expose-gc");
    const gc = runInNewContext("gc") as (() => void) | undefined;
    v8.setFlagsFromString("--no-expose-gc");
    if (typeof gc === "function") return gc;
  } catch {
    // Fall through to the no-op below — better to skip the workaround than crash.
  }
  return () => {
    /* not available in this runtime; scanning still works, just without the safety net */
  };
}

const forcedGc = createForcedGc();

/** Call between parsing/analyzing files in a multi-file scan. See module doc above. */
export function collectGarbageToAvoidTreeSitterCorruption(): void {
  forcedGc();
}
