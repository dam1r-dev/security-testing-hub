// The scan the web page runs: the dropped files are mounted into the virtual file system and the ordinary scanPath
// runs on them. The result has the same shape as `security-hub scan --format json` (the report viewer on the page also
// opens JSON files made on the command line), plus the "fix with AI" prompts that `security-hub ui` shows.
import { computeScore, fixPromptFor, scanPath, ScanSummary, toFixPrompt } from "../src/index";
import * as virtualFs from "./shims/fs";
import type { MountedFile } from "./shims/fs";

export type { MountedFile };

export const ROOT = "/project";

export interface WebScanOptions {
  includeTests?: boolean;
  onProgress?: (done: number, total: number) => void;
}

export type WebScanResult = ScanSummary & { score: ReturnType<typeof computeScore>; fixPromptAll: string };

export function scanFiles(files: MountedFile[], options: WebScanOptions = {}): WebScanResult {
  virtualFs.mount(ROOT, files);
  try {
    const summary = scanPath(ROOT, { includeTests: options.includeTests, onProgress: options.onProgress });
    const withPrompts: ScanSummary = {
      ...summary,
      results: summary.results.map((r) => ({
        ...r,
        findings: r.findings.map((f) => ({ ...f, fixPrompt: fixPromptFor(f, { relativeTo: ROOT }) })),
      })),
    };
    const fixPromptAll = toFixPrompt(summary, { relativeTo: ROOT });
    // Paths in the report are relative to the dropped folder, like a scan started inside it.
    const relative = JSON.parse(JSON.stringify(withPrompts).split(`${ROOT}/`).join("")) as ScanSummary;
    return { ...relative, score: computeScore(relative), fixPromptAll };
  } finally {
    virtualFs.unmount();
  }
}
