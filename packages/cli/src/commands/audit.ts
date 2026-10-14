import { execFileSync } from "child_process";
import * as fs from "fs";
import * as path from "path";
import { Finding, ScanResult, Severity } from "security-hub-scanner";

/**
 * `security-hub scan --audit`: known vulnerabilities in the packages your project depends on, from npm's own advisory
 * database. This is the ONE feature that talks to the network (`npm audit` sends the names and versions of your
 * dependencies to the npm registry), so it only runs when asked for, and it never installs anything.
 */

type Exec = (cwd: string) => string;

interface AuditVia {
  title?: string;
  url?: string;
  severity?: string;
  range?: string;
}

interface AuditVulnerability {
  name: string;
  severity: string;
  isDirect: boolean;
  via: Array<AuditVia | string>;
  fixAvailable?: boolean | { name: string; version: string; isSemVerMajor: boolean };
}

const SEVERITY: Record<string, Severity> = { critical: "critical", high: "high", moderate: "medium", low: "low", info: "low" };
const RANK: Record<Severity, number> = { low: 0, medium: 1, high: 2, critical: 3 };

/** How to start npm: on Windows `npm` is a .cmd file, which needs a shell, so run npm's own script with this node instead. */
function npmCommand(): { file: string; args: string[]; shell: boolean } {
  if (process.platform === "win32") {
    const script = path.join(path.dirname(process.execPath), "node_modules", "npm", "bin", "npm-cli.js");
    if (fs.existsSync(script)) return { file: process.execPath, args: [script, "audit", "--json"], shell: false };
    return { file: "npm.cmd", args: ["audit", "--json"], shell: true };
  }
  return { file: "npm", args: ["audit", "--json"], shell: false };
}

const defaultExec: Exec = (cwd) => {
  const { file, args, shell } = npmCommand();
  try {
    return execFileSync(file, args, { cwd, timeout: 90_000, maxBuffer: 64 * 1024 * 1024, shell }).toString();
  } catch (error) {
    // `npm audit` exits non-zero when it finds something: the report is still on stdout
    const out = (error as { stdout?: Buffer | string }).stdout;
    if (out && out.toString().trim().startsWith("{")) return out.toString();
    throw error;
  }
};

function lineOf(text: string, name: string): number {
  const index = text.indexOf(`"${name}"`);
  return index < 0 ? 1 : text.slice(0, index).split("\n").length;
}

function installedVersion(projectDir: string, name: string): string | undefined {
  try {
    return JSON.parse(fs.readFileSync(path.join(projectDir, "node_modules", name, "package.json"), "utf8")).version as string;
  } catch {
    // not installed: the lock file knows
  }
  for (const lock of ["package-lock.json", "npm-shrinkwrap.json"]) {
    try {
      const parsed = JSON.parse(fs.readFileSync(path.join(projectDir, lock), "utf8"));
      const version = parsed.packages?.[`node_modules/${name}`]?.version as string | undefined;
      if (version) return version;
    } catch {
      // try the next one
    }
  }
  return undefined;
}

function fixText(vulnerability: AuditVulnerability): string {
  const fix = vulnerability.fixAvailable;
  if (fix && typeof fix === "object") {
    return fix.isSemVerMajor
      ? `Upgrade with \`npm install ${fix.name}@${fix.version}\` (a major version: read its changelog first).`
      : `Fix with \`npm install ${fix.name}@${fix.version}\` or \`npm audit fix\`.`;
  }
  return fix === true ? "Fix with `npm audit fix`." : "No fixed version is published yet: look for an alternative package or pin a safe version.";
}

/** Turns an `npm audit --json` report into findings located in package.json. */
export function parseAudit(report: string, projectDir: string): { findings: Finding[]; error?: string } {
  let parsed: { vulnerabilities?: Record<string, AuditVulnerability>; error?: { summary?: string; code?: string } };
  try {
    parsed = JSON.parse(report);
  } catch {
    return { findings: [], error: "npm audit did not return a report" };
  }
  if (parsed.error) return { findings: [], error: parsed.error.summary ?? parsed.error.code ?? "npm audit failed" };

  const packageJson = path.join(projectDir, "package.json");
  const text = fs.existsSync(packageJson) ? fs.readFileSync(packageJson, "utf8") : "";
  const make = (line: number, severity: Severity, message: string, source: string, sink: string): Finding => ({
    ruleId: "vulnerable-dependency",
    severity,
    confidence: "high",
    message,
    location: { file: packageJson, startLine: line, startColumn: 1, endLine: line, endColumn: 1 },
    sourceSnippet: source,
    sinkSnippet: sink,
  });

  const findings: Finding[] = [];
  const transitive: AuditVulnerability[] = [];
  for (const vulnerability of Object.values(parsed.vulnerabilities ?? {})) {
    if (!vulnerability.isDirect) {
      transitive.push(vulnerability);
      continue;
    }
    const advisories = vulnerability.via.filter((v): v is AuditVia => typeof v === "object");
    const titles = [...new Set(advisories.map((a) => a.title).filter((t): t is string => !!t))].slice(0, 3);
    const url = advisories.find((a) => a.url)?.url;
    const version = installedVersion(projectDir, vulnerability.name);
    const label = version ? `${vulnerability.name}@${version}` : vulnerability.name;
    const severity = SEVERITY[vulnerability.severity] ?? "medium";
    findings.push(
      make(
        lineOf(text, vulnerability.name),
        severity,
        `${label} has ${advisories.length > 1 ? `${advisories.length} known vulnerabilities` : "a known vulnerability"}${titles.length > 0 ? `: ${titles.join("; ")}` : ""}${url ? ` (${url})` : ""}. ${fixText(vulnerability)}`,
        label,
        titles[0] ?? "known vulnerability",
      ),
    );
  }
  if (transitive.length > 0) {
    const worst = transitive.reduce<Severity>((max, v) => ((RANK[SEVERITY[v.severity] ?? "medium"] ?? 1) > RANK[max] ? (SEVERITY[v.severity] ?? "medium") : max), "low");
    const names = transitive.map((v) => v.name).sort();
    findings.push(
      make(
        1,
        worst,
        `${transitive.length} vulnerable package(s) that your dependencies pull in (${names.slice(0, 6).join(", ")}${names.length > 6 ? ", ..." : ""}); the worst is ${worst}. ` +
          "Run `npm audit` for the details and `npm audit fix` to update what can be updated without breaking changes.",
        `${transitive.length} transitive`,
        names.slice(0, 3).join(", "),
      ),
    );
  }
  return { findings };
}

/** Runs `npm audit` in `projectDir` (needs package.json and a lock file) and returns its findings as a scan result. */
export function auditResults(projectDir: string, exec: Exec = defaultExec): { results: ScanResult[]; warning?: string } {
  if (!fs.existsSync(path.join(projectDir, "package.json"))) return { results: [], warning: "--audit: no package.json in this folder, so there are no dependencies to check." };
  if (!["package-lock.json", "npm-shrinkwrap.json"].some((lock) => fs.existsSync(path.join(projectDir, lock)))) {
    return { results: [], warning: "--audit: no package-lock.json. Create one without installing anything: `npm install --package-lock-only`, then run it again." };
  }
  let report: string;
  try {
    report = exec(projectDir);
  } catch (error) {
    return { results: [], warning: `--audit: could not run \`npm audit\` (${(error as Error).message.split("\n")[0]}). Is npm installed and are you online?` };
  }
  const { findings, error } = parseAudit(report, projectDir);
  if (error) return { results: [], warning: `--audit: ${error}` };
  return { results: findings.length > 0 ? [{ file: path.join(projectDir, "package.json"), findings }] : [] };
}
