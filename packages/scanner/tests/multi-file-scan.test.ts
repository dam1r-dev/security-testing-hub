import * as path from "path";
import { scanPath } from "../src/index";

// Regression test for a real node-tree-sitter bug: scanning several files
// back-to-back in one process could silently corrupt a later file's parse
// (taint that should be found wasn't), reproducible independent of file
// content/size, fixed by forcing a GC between files (see
// src/parsers/gc-workaround.ts). This scans the whole Next.js fixture
// directory (not a single file in isolation) specifically to catch a
// regression of that cross-file corruption.
describe("scanPath multi-file stability", () => {
  const FIXTURE_APP = path.resolve(__dirname, "../../../examples/vulnerable-nextjs-app");

  it("finds every planted vulnerability across multiple files scanned in one run, consistently", () => {
    for (let attempt = 0; attempt < 3; attempt++) {
      const summary = scanPath(FIXTURE_APP);
      const byFile = new Map(summary.results.map((r) => [path.basename(path.dirname(r.file)), r.findings]));

      expect(byFile.get("search")?.some((f) => f.ruleId === "sql-injection")).toBe(true);
      expect(byFile.get("proxy")?.some((f) => f.ruleId === "ssrf")).toBe(true);
      expect(byFile.get("ping")?.some((f) => f.ruleId === "command-injection")).toBe(true);
      expect(byFile.get("greet")?.some((f) => f.ruleId === "xss")).toBe(true);
      expect(byFile.get("user-safe")).toEqual([]);
    }
  });
});
