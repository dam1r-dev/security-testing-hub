import { Command } from "commander";
import chalk from "chalk";
import { runScan } from "./commands/scan";
import { Severity } from "@security-hub/scanner";

const VALID_SEVERITIES: Severity[] = ["low", "medium", "high", "critical"];

function parseSeverity(value: string): Severity {
  const normalized = value.toLowerCase() as Severity;
  if (!VALID_SEVERITIES.includes(normalized)) {
    throw new Error(`Invalid severity "${value}". Expected one of: ${VALID_SEVERITIES.join(", ")}`);
  }
  return normalized;
}

export function run(argv: string[]): void {
  const program = new Command();

  program
    .name("security-hub")
    .description("Open-source SAST scanner for Node.js/Express apps (SQLi, XSS, command injection, path traversal, CSRF)")
    .version("0.1.0");

  program
    .command("scan <path>")
    .description("Scan a file or directory for vulnerabilities")
    .option("-f, --format <format>", "output format: text | json | sarif", "text")
    .option("-o, --out <file>", "write output to a file instead of stdout")
    .option("-s, --severity <level>", "only report findings at or above this severity (low|medium|high|critical)")
    .option("--fail-on <level>", "exit with code 1 if any finding is at or above this severity (for CI)")
    .action((targetPath: string, opts) => {
      const format = opts.format;
      if (!["text", "json", "sarif"].includes(format)) {
        console.error(chalk.red(`Invalid format "${format}". Expected: text | json | sarif`));
        process.exitCode = 2;
        return;
      }
      const exitCode = runScan(targetPath, {
        format,
        out: opts.out,
        severity: opts.severity ? parseSeverity(opts.severity) : undefined,
        failOn: opts.failOn ? parseSeverity(opts.failOn) : undefined,
      });
      process.exitCode = exitCode;
    });

  program
    .command("lab <name>")
    .description("Spin up a Docker vulnerability lab to practice against (coming in Phase 6)")
    .action((name: string) => {
      console.log(chalk.yellow(`'lab ${name}' isn't implemented yet — Docker labs land in Phase 6 of the dev plan.`));
      process.exitCode = 1;
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
