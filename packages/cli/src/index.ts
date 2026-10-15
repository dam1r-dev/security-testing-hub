import { Command } from "commander";
import chalk from "chalk";
import { runScan } from "./commands/scan";
import { runLab } from "./commands/lab";
import { runUi } from "./commands/ui";
import { runFix } from "./commands/fix";
import { runBaseline } from "./commands/baseline";
import { Severity } from "security-hub-scanner";

// Read at runtime so `--version` can never drift from the published package.json
// (dist/index.js sits one level below the package root).
// eslint-disable-next-line @typescript-eslint/no-var-requires, @typescript-eslint/no-require-imports
const PACKAGE_VERSION: string = require("../package.json").version;

const VALID_SEVERITIES: Severity[] = ["low", "medium", "high", "critical"];

function parseSeverity(value: string): Severity {
  const normalized = value.toLowerCase() as Severity;
  if (!VALID_SEVERITIES.includes(normalized)) {
    throw new Error(`Invalid severity "${value}". Expected one of: ${VALID_SEVERITIES.join(", ")}`);
  }
  return normalized;
}

function collect(value: string, previous: string[]): string[] {
  return [...previous, value];
}

export function run(argv: string[]): void {
  const program = new Command();

  program
    .name("security-hub")
    .description("Open-source SAST scanner for Node.js/Express apps (SQLi, XSS, command injection, path traversal, CSRF)")
    .version(PACKAGE_VERSION);

  program
    .command("scan <path>")
    .description("Scan a file or directory for vulnerabilities")
    .option("-f, --format <format>", "output format: text | json | sarif | html | markdown | github | prompt", "text")
    .option("-o, --out <file>", "write output to a file instead of stdout (html always writes to a file)")
    .option("-s, --severity <level>", "only report findings at or above this severity (low|medium|high|critical)")
    .option("--fail-on <level>", "exit with code 1 if any finding is at or above this severity (for CI)")
    .option("--ignore <pattern>", "skip files/folders matching this pattern (repeatable; also reads .security-hub-ignore)", collect, [])
    .option("--changed-since <ref>", "report only findings in files changed since this git ref, e.g. origin/main (the whole project is still scanned)")
    .option("--include-tests", "also scan test folders and *.test.* / *.spec.* files (skipped by default)")
    .option("--audit", "also check your dependencies for known vulnerabilities (runs `npm audit`; sends dependency names and versions to the npm registry)")
    .option("--config <file>", "read settings from this file instead of .security-hub.json in the project")
    .option("--no-config", "ignore .security-hub.json")
    .option("--baseline <file>", "hide the findings listed in this baseline file (default: .security-hub-baseline.json in the project, when there is one)")
    .option("--no-baseline", "report existing findings too, even if the project has a baseline")
    .action((targetPath: string, opts) => {
      const format = opts.format;
      if (!["text", "json", "sarif", "html", "markdown", "github", "prompt"].includes(format)) {
        console.error(chalk.red(`Invalid format "${format}". Expected: text | json | sarif | html | markdown | github | prompt`));
        process.exitCode = 2;
        return;
      }
      const exitCode = runScan(targetPath, {
        format,
        out: opts.out,
        severity: opts.severity ? parseSeverity(opts.severity) : undefined,
        failOn: opts.failOn ? parseSeverity(opts.failOn) : undefined,
        ignore: opts.ignore.length > 0 ? opts.ignore : undefined,
        includeTests: opts.includeTests,
        changedSince: opts.changedSince,
        audit: opts.audit ? true : undefined,
        config: opts.config,
        baseline: opts.baseline,
      });
      process.exitCode = exitCode;
    });

  program
    .command("baseline [path]")
    .description("Record the findings that exist today in .security-hub-baseline.json, so later scans report only new ones (to adopt the scanner in an old project)")
    .option("-o, --out <file>", "write the baseline here instead of .security-hub-baseline.json in the project")
    .option("--ignore <pattern>", "skip files/folders matching this pattern (repeatable)", collect, [])
    .option("--include-tests", "also record findings in test folders")
    .option("--config <file>", "read settings from this file instead of .security-hub.json in the project")
    .option("--no-config", "ignore .security-hub.json")
    .action((targetPath: string | undefined, opts) => {
      process.exitCode = runBaseline(targetPath ?? ".", {
        out: opts.out,
        ignore: opts.ignore.length > 0 ? opts.ignore : undefined,
        includeTests: opts.includeTests ? true : undefined,
        config: opts.config,
      });
    });

  program
    .command("ui [path]")
    .description("Open the local web interface: pick a folder, click Scan, see the score (no terminal needed)")
    .option("-p, --port <port>", "port to listen on (default 4173; the next free one is used if taken)")
    .option("--no-open", "do not open the browser automatically")
    .action(async (targetPath: string | undefined, opts) => {
      const port = opts.port === undefined ? undefined : Number(opts.port);
      if (port !== undefined && (!Number.isInteger(port) || port < 0 || port > 65535)) {
        console.error(chalk.red(`Invalid port "${opts.port}". Expected a number between 0 and 65535.`));
        process.exitCode = 2;
        return;
      }
      process.exitCode = await runUi({ path: targetPath, port, open: opts.open });
    });

  program
    .command("fix <path>")
    .description("Fix what can be fixed safely: SQL parameters, JWT expiry, secrets into .env, CORS origins, Supabase RLS migration. Shows a diff; changes nothing without --write")
    .option("--write", "apply the changes (default: only show them)")
    .option("--only <rule>", "fix only this rule (repeatable): sql-injection | insecure-jwt | hardcoded-secret | insecure-cors | supabase-rls", collect, [])
    .option("--force", "change files even if git shows uncommitted edits in them")
    .option("--ignore <pattern>", "skip files/folders matching this pattern (repeatable)", collect, [])
    .option("--include-tests", "also fix test folders and *.test.* files")
    .action((targetPath: string, opts) => {
      process.exitCode = runFix(targetPath, {
        write: !!opts.write,
        only: opts.only.length > 0 ? opts.only : undefined,
        force: !!opts.force,
        ignore: opts.ignore.length > 0 ? opts.ignore : undefined,
        includeTests: !!opts.includeTests,
      });
    });

  program
    .command("lab [name]")
    .description("Start (or stop, with --stop) a Docker vulnerability lab to practice against")
    .option("--stop", "stop and clean up the lab instead of starting it")
    .action((name: string | undefined, opts) => {
      process.exitCode = runLab(name, { stop: !!opts.stop });
    });

  program
    .command("docs")
    .description("Open the rule documentation (coming in Phase 7)")
    .action(() => {
      console.log(chalk.yellow("'docs' isn't implemented yet — full rule docs land in Phase 7 of the dev plan."));
      console.log("For now, see docs/rules.md in the repo.");
    });

  program.parse(argv);
}
