import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { auditResults, parseAudit } from "../src/commands/audit";

// `scan --audit`: npm's advisories turned into findings. The npm call is replaced by a fixed report, so no test
// touches the network.

const dirs: string[] = [];
afterAll(() => dirs.forEach((d) => fs.rmSync(d, { recursive: true, force: true })));

function project(withLock = true): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "sh-audit-"));
  dirs.push(dir);
  fs.writeFileSync(path.join(dir, "package.json"), `{\n  "name": "demo",\n  "dependencies": {\n    "lodash": "4.17.10",\n    "express": "4.0.0"\n  }\n}\n`);
  if (withLock) fs.writeFileSync(path.join(dir, "package-lock.json"), JSON.stringify({ packages: { "node_modules/lodash": { version: "4.17.10" } } }));
  return dir;
}

const REPORT = JSON.stringify({
  auditReportVersion: 2,
  vulnerabilities: {
    lodash: {
      name: "lodash",
      severity: "high",
      isDirect: true,
      via: [
        { source: 1, name: "lodash", title: "Prototype Pollution in lodash", url: "https://github.com/advisories/GHSA-p6mc-m468-83gw", severity: "high", range: "<4.17.20" },
        { source: 2, name: "lodash", title: "Command Injection in lodash", url: "https://github.com/advisories/GHSA-35jh-r3h4-6jhm", severity: "high", range: "<4.17.21" },
      ],
      fixAvailable: { name: "lodash", version: "4.17.21", isSemVerMajor: false },
    },
    express: { name: "express", severity: "moderate", isDirect: true, via: ["qs"], fixAvailable: { name: "express", version: "5.0.0", isSemVerMajor: true } },
    qs: { name: "qs", severity: "critical", isDirect: false, via: [{ title: "qs prototype poisoning", url: "https://github.com/advisories/GHSA-hrpp-h998-j3pp", severity: "critical" }], fixAvailable: true },
    minimist: { name: "minimist", severity: "low", isDirect: false, via: [{ title: "x", severity: "low" }], fixAvailable: false },
  },
});

describe("parseAudit", () => {
  it("one finding per vulnerable direct dependency, with the installed version, the advisories and the fix", () => {
    const dir = project();
    const { findings, error } = parseAudit(REPORT, dir);
    expect(error).toBeUndefined();
    const lodash = findings.find((f) => f.sourceSnippet.startsWith("lodash"));
    expect(lodash).toMatchObject({ ruleId: "vulnerable-dependency", severity: "high", confidence: "high" });
    expect(lodash?.sourceSnippet).toBe("lodash@4.17.10");
    expect(lodash?.message).toContain("2 known vulnerabilities");
    expect(lodash?.message).toContain("Prototype Pollution in lodash; Command Injection in lodash");
    expect(lodash?.message).toContain("npm install lodash@4.17.21");
    expect(lodash?.location.file).toBe(path.join(dir, "package.json"));
    expect(lodash?.location.startLine).toBe(4); // the line of "lodash" in package.json
    const express = findings.find((f) => f.sourceSnippet.startsWith("express"));
    expect(express?.severity).toBe("medium"); // npm "moderate"
    expect(express?.message).toContain("a major version");
    expect(express?.location.startLine).toBe(5);
  });

  it("packages your dependencies pull in are one finding, ranked by the worst of them", () => {
    const { findings } = parseAudit(REPORT, project());
    const transitive = findings.filter((f) => f.sinkSnippet.includes("minimist") || f.sourceSnippet.includes("transitive"));
    expect(transitive).toHaveLength(1);
    expect(transitive[0]).toMatchObject({ severity: "critical" });
    expect(transitive[0]?.message).toContain("2 vulnerable package(s) that your dependencies pull in (minimist, qs)");
    expect(findings).toHaveLength(3);
  });

  it("reports an npm error instead of pretending the project is clean", () => {
    expect(parseAudit(JSON.stringify({ error: { code: "ENOLOCK", summary: "This command requires an existing lockfile." } }), project()).error).toContain("lockfile");
    expect(parseAudit("not json", project()).error).toBeDefined();
  });

  it("a clean report has no findings", () => {
    expect(parseAudit(JSON.stringify({ auditReportVersion: 2, vulnerabilities: {} }), project()).findings).toEqual([]);
  });
});

describe("auditResults", () => {
  it("returns package.json as a scanned file with the findings", () => {
    const dir = project();
    const { results, warning } = auditResults(dir, () => REPORT);
    expect(warning).toBeUndefined();
    expect(results).toHaveLength(1);
    expect(results[0]?.file).toBe(path.join(dir, "package.json"));
    expect(results[0]?.findings).toHaveLength(3);
  });

  it("says what to do when there is no lock file, and never runs npm in that case", () => {
    const exec = jest.fn(() => REPORT);
    const { results, warning } = auditResults(project(false), exec);
    expect(results).toEqual([]);
    expect(warning).toContain("npm install --package-lock-only");
    expect(exec).not.toHaveBeenCalled();
  });

  it("a failing npm (offline, not installed) is a warning, not a crash", () => {
    const { results, warning } = auditResults(project(), () => {
      throw new Error("getaddrinfo ENOTFOUND registry.npmjs.org");
    });
    expect(results).toEqual([]);
    expect(warning).toContain("could not run `npm audit`");
    expect(warning).toContain("ENOTFOUND");
  });

  it("a folder without package.json has nothing to check", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "sh-audit-empty-"));
    dirs.push(dir);
    expect(auditResults(dir, () => REPORT).warning).toContain("no package.json");
  });
});
