import { execFileSync } from "child_process";
import * as fs from "fs";
import * as path from "path";
import { Analyzer } from "../src/analyzers/base-analyzer";
import { BudgetExceeded, checkBudgetNow, startBudget } from "../src/budget";
import { scanSource } from "../src/index";
import { Finding } from "../src/types";

// A scan reads code written by someone else. A hostile file must cost one note, never the whole scan.

jest.setTimeout(120_000);

const DIST = path.resolve(__dirname, "..", "dist", "index.js");
const CHILD = path.join(__dirname, "helpers", "hostile-child.js");

/** Runs one hostile input through the BUILT scanner in its own process (see helpers/hostile-child.js for why). */
function hostile(name: string): { threw: boolean; ms: number; message?: string; secretFindings?: number; note?: string } {
  if (!fs.existsSync(DIST)) throw new Error("packages/scanner/dist is missing: run `npm run build` first (npm test does)");
  return JSON.parse(execFileSync(process.execPath, [CHILD, name], { encoding: "utf8", timeout: 100_000 }));
}

describe("deep and huge files do not crash the scan", () => {
  it("a 60 000-term expression (a 60 000-deep tree) is analysed without a stack overflow", () => {
    expect(hostile("deep-expression").threw).toBe(false);
  });

  it("a 30 000-link member chain and 3 000 nested parentheses", () => {
    expect(hostile("member-chain").threw).toBe(false);
    expect(hostile("parentheses").threw).toBe(false);
  });

  it("an object with thousands of properties that look like secrets stays fast and is capped", () => {
    const result = hostile("many-secrets");
    expect(result.threw).toBe(false);
    expect(result.ms).toBeLessThan(20_000); // it was quadratic: 40 000 properties took over a minute
    expect(result.secretFindings).toBeLessThanOrEqual(500);
  });
});

describe("one failing check does not take the file, or the scan, down", () => {
  const finding: Finding = {
    ruleId: "xss",
    severity: "high",
    confidence: "high",
    message: "kept",
    location: { file: "a.js", startLine: 1, startColumn: 1, endLine: 1, endColumn: 2 },
    sourceSnippet: "",
    sinkSnippet: "",
  };
  const good: Analyzer = { analyze: () => [finding] };
  class Exploding implements Analyzer {
    analyze(): Finding[] {
      throw new RangeError("Maximum call stack size exceeded");
    }
  }

  it("keeps the findings of the other checks and says which check could not finish", () => {
    const result = scanSource("const a = 1;", "a.js", [good, new Exploding(), good]);
    expect(result.findings).toHaveLength(2);
    expect(result.parseError).toContain("One check (Exploding) could not finish: Maximum call stack size exceeded.");
  });

  it("a used-up time budget stops the analysis of that file only", () => {
    const slow: Analyzer = {
      analyze: () => {
        const end = startBudget(1);
        try {
          const until = Date.now() + 20;
          while (Date.now() < until) {
            /* wait for the budget to run out */
          }
          checkBudgetNow();
        } finally {
          end();
        }
        return [];
      },
    };
    // the analyzer's own tiny budget throws inside scanSource's guard, which reports it without failing the scan
    const result = scanSource("const a = 1;", "a.js", [slow, good]);
    expect(result.parseError).toMatch(/Analysis stopped after 15 s/);
    expect(result.findings).toHaveLength(0); // the run stopped at the budget: the check after it did not run
    // and the next file is scanned normally
    expect(scanSource("const a = 1;", "b.js", [good]).findings).toHaveLength(1);
  });

  it("the budget is restored after a scan, so nothing outside it is cut short", () => {
    scanSource("const a = 1;", "a.js", [good]);
    expect(() => checkBudgetNow()).not.toThrow();
    const end = startBudget(1);
    end();
    expect(() => checkBudgetNow()).not.toThrow();
    expect(new BudgetExceeded().message).toContain("too long");
  });
});
