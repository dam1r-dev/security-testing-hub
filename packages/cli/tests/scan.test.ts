import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { runScan } from "../src/commands/scan";

const FIXTURE_APP = path.resolve(__dirname, "../../../examples/vulnerable-express-app");

describe("runScan against the vulnerable-express-app fixture", () => {
  it("finds all five vulnerability classes, none in the safe route", () => {
    const outFile = path.join(os.tmpdir(), `security-hub-test-${Date.now()}.json`);
    const exitCode = runScan(FIXTURE_APP, { format: "json", out: outFile });
    const summary = JSON.parse(fs.readFileSync(outFile, "utf8"));
    fs.unlinkSync(outFile);

    const ruleIds = new Set(
      summary.results.flatMap((r: { findings: { ruleId: string }[] }) => r.findings.map((f) => f.ruleId)),
    );

    expect(ruleIds).toEqual(
      new Set(["sql-injection", "xss", "command-injection", "path-traversal", "csrf"]),
    );
    // Safe, parameterized route must not be flagged.
    const usersFile = summary.results.find((r: { file: string }) => r.file.endsWith("users.js"));
    expect(usersFile.findings.some((f: { location: { startLine: number } }) => f.location.startLine >= 17)).toBe(
      false,
    );
    expect(exitCode).toBe(0);
  });

  it("exits with code 1 when --fail-on threshold is crossed", () => {
    const outFile = path.join(os.tmpdir(), `security-hub-test-${Date.now()}-2.json`);
    const exitCode = runScan(FIXTURE_APP, { format: "json", out: outFile, failOn: "critical" });
    fs.unlinkSync(outFile);
    expect(exitCode).toBe(1);
  });

  it("produces valid SARIF output", () => {
    const outFile = path.join(os.tmpdir(), `security-hub-test-${Date.now()}-3.sarif`);
    runScan(FIXTURE_APP, { format: "sarif", out: outFile });
    const sarif = JSON.parse(fs.readFileSync(outFile, "utf8"));
    fs.unlinkSync(outFile);
    expect(sarif.version).toBe("2.1.0");
    expect(sarif.runs[0].results.length).toBeGreaterThan(0);
  });
});
