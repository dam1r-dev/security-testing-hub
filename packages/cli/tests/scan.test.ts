import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { runScan } from "../src/commands/scan";

const FIXTURE_APP = path.resolve(__dirname, "../../../examples/vulnerable-express-app");
const NEXTJS_FIXTURE_APP = path.resolve(__dirname, "../../../examples/vulnerable-nextjs-app");

describe("runScan against the vulnerable-express-app fixture", () => {
  it("finds all eleven vulnerability classes, none in the safe routes", () => {
    const outFile = path.join(os.tmpdir(), `security-hub-test-${Date.now()}.json`);
    const exitCode = runScan(FIXTURE_APP, { format: "json", out: outFile });
    const summary = JSON.parse(fs.readFileSync(outFile, "utf8"));
    fs.unlinkSync(outFile);

    const ruleIds = new Set(
      summary.results.flatMap((r: { findings: { ruleId: string }[] }) => r.findings.map((f) => f.ruleId)),
    );

    expect(ruleIds).toEqual(
      new Set([
        "sql-injection",
        "xss",
        "command-injection",
        "path-traversal",
        "csrf",
        "ssrf",
        "idor",
        "broken-access-control",
        "insecure-role-assignment",
        "insecure-file-upload",
        "username-enumeration",
      ]),
    );
    // Safe, parameterized query in users.js (the /user-safe/:id route) must not be
    // flagged as SQL injection, even though it's still flagged for IDOR (no
    // ownership check) — that's a separate, still-real concern in this fixture.
    const usersFile = summary.results.find((r: { file: string }) => r.file.endsWith("users.js"));
    expect(
      usersFile.findings.some(
        (f: { ruleId: string; location: { startLine: number } }) =>
          f.ruleId === "sql-injection" && f.location.startLine >= 17,
      ),
    ).toBe(false);
    // Safe, ownership-checked route in accounts.js must not be flagged as IDOR.
    const accountsFile = summary.results.find((r: { file: string }) => r.file.endsWith("accounts.js"));
    expect(accountsFile.findings.every((f: { ruleId: string }) => f.ruleId !== "idor")).toBe(false); // vulnerable route IS flagged
    const accountsSafeFindings = accountsFile.findings.filter(
      (f: { location: { startLine: number } }) => f.location.startLine >= 9,
    );
    expect(accountsSafeFindings).toHaveLength(0);
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

describe("runScan against the vulnerable-nextjs-app fixture", () => {
  it("finds all seven vulnerability classes via Next.js App Router conventions, none in the safe routes", () => {
    const outFile = path.join(os.tmpdir(), `security-hub-test-nextjs-${Date.now()}.json`);
    const exitCode = runScan(NEXTJS_FIXTURE_APP, { format: "json", out: outFile });
    const summary = JSON.parse(fs.readFileSync(outFile, "utf8"));
    fs.unlinkSync(outFile);

    const ruleIds = new Set(
      summary.results.flatMap((r: { findings: { ruleId: string }[] }) => r.findings.map((f) => f.ruleId)),
    );
    expect(ruleIds).toEqual(
      new Set(["sql-injection", "ssrf", "xss", "command-injection", "csrf", "idor", "broken-access-control"]),
    );

    const safeUserRoute = summary.results.find((r: { file: string }) => /user-safe[/\\]route\.ts$/.test(r.file));
    expect(safeUserRoute.findings).toHaveLength(0);

    const safeAccountRoute = summary.results.find((r: { file: string }) =>
      /accounts-safe[/\\]\[accountId\][/\\]route\.ts$/.test(r.file),
    );
    expect(safeAccountRoute.findings).toHaveLength(0);

    expect(exitCode).toBe(0);
  });
});
