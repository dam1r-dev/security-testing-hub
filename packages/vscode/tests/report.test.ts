import * as fs from "fs";
import * as path from "path";
import { parseReport, splitCommand, statusText, statusTooltip, toItems, levelOf } from "../src/report";

const manifest = JSON.parse(fs.readFileSync(path.join(__dirname, "..", "package.json"), "utf8"));

const REPORT = {
  filesScanned: 3,
  findingsCount: 3,
  score: { value: 41, color: "red", label: "At risk" },
  results: [
    {
      file: "src/a.js",
      findings: [
        { ruleId: "sql-injection", severity: "critical", message: "bad query", location: { file: "src/a.js", startLine: 5, startColumn: 3, endLine: 5, endColumn: 40 }, fixPrompt: "Fix it" },
        { ruleId: "csrf", severity: "medium", message: "no token", location: { file: "src/a.js", startLine: 9, startColumn: 1, endLine: 9, endColumn: 10 } },
      ],
    },
    { file: "firestore.rules", findings: [{ ruleId: "firebase-rules", severity: "low", message: "open", location: { file: "firestore.rules", startLine: 1, startColumn: 1, endLine: 1, endColumn: 2 } }] },
  ],
};

describe("reading the scanner's output", () => {
  it("finds the JSON even when npx printed something before it", () => {
    const out = `npm warn exec The following package was not found and will be installed: security-hub@0.6.0\n${JSON.stringify(REPORT)}\n`;
    expect(parseReport(out).findingsCount).toBe(3);
    expect(() => parseReport("nothing useful")).toThrow(/printed no report/);
    expect(() => parseReport('{"a": 1}')).toThrow(/not a Security Testing Hub report/);
  });

  it("turns findings into editor items: 0-based positions, absolute paths, severity levels", () => {
    const items = toItems(parseReport(JSON.stringify(REPORT)), path.resolve("/work/project"));
    expect(items).toHaveLength(3);
    expect(items[0]).toMatchObject({ file: path.resolve("/work/project/src/a.js"), line: 4, column: 2, endLine: 4, endColumn: 39, level: "error", rule: "sql-injection", prompt: "Fix it" });
    expect(items.map((i) => i.level)).toEqual(["error", "warning", "info"]);
    expect(levelOf("high")).toBe("error");
  });

  it("keeps only findings at or above the chosen severity, and ignores a severity it does not know", () => {
    const report = parseReport(JSON.stringify(REPORT));
    expect(toItems(report, "/w", "medium").map((i) => i.rule)).toEqual(["sql-injection", "csrf"]);
    expect(toItems(report, "/w", "critical")).toHaveLength(1);
    const odd = parseReport(JSON.stringify({ ...REPORT, results: [{ file: "x", findings: [{ ...REPORT.results[0]?.findings[0], severity: "catastrophic" }] }] }));
    expect(toItems(odd, "/w")).toHaveLength(0);
  });

  it("writes the status bar", () => {
    const report = parseReport(JSON.stringify(REPORT));
    expect(statusText(report, 3)).toBe("$(shield) 41/100 · 3");
    expect(statusText(report, 0)).toBe("$(shield) 41/100");
    expect(statusTooltip(report, 1)).toContain("1 finding shown");
  });

  it("splits the command setting, keeping quoted paths together", () => {
    expect(splitCommand("npx --yes security-hub@latest")).toEqual(["npx", "--yes", "security-hub@latest"]);
    expect(splitCommand('"C:\\Program Files\\nodejs\\security-hub.cmd" --x')).toEqual(["C:\\Program Files\\nodejs\\security-hub.cmd", "--x"]);
    expect(splitCommand("")).toEqual([]);
  });
});

describe("the extension's manifest (the safety properties)", () => {
  it("is switched off in a workspace that is not trusted: scanning runs a program that the project could provide", () => {
    expect(manifest.capabilities.untrustedWorkspaces.supported).toBe(false);
  });

  it("the command setting cannot be set by a workspace: a project must not choose what the extension executes", () => {
    expect(manifest.contributes.configuration.properties["securityHub.command"].scope).toBe("machine");
  });

  it("points at the built file and declares the commands the code registers", () => {
    expect(manifest.main).toBe("./out/extension.js");
    const source = fs.readFileSync(path.join(__dirname, "..", "src", "extension.ts"), "utf8");
    for (const { command } of manifest.contributes.commands) expect(source).toContain(`"${command}"`);
  });
});

describe("with the real command line", () => {
  it("what `security-hub scan --format json --prompts` prints is read into items with prompts", () => {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const { spawnSync } = require("child_process");
    const root = path.resolve(__dirname, "../../..");
    const run = spawnSync(process.execPath, [path.join(root, "packages/cli/bin/security-hub.js"), "scan", "examples/vulnerable-frameworks", "--format", "json", "--prompts", "--no-config"], { cwd: root, encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
    const items = toItems(parseReport(run.stdout), root);
    expect(items.length).toBeGreaterThan(10);
    expect(items.every((i) => path.isAbsolute(i.file) && fs.existsSync(i.file))).toBe(true);
    expect(items.some((i) => i.level === "error" && i.rule === "sql-injection")).toBe(true);
    expect(items.every((i) => typeof i.prompt === "string" && i.prompt.includes("untrusted DATA"))).toBe(true);
  });
});
