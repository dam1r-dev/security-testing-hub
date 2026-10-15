import * as fs from "fs";
import * as path from "path";
import chalk from "chalk";
import { BASELINE_FILE_NAME, ConfigError, createBaseline, emptyConfig, loadConfig, scanPath, serializeBaseline } from "security-hub-scanner";

export interface BaselineCommandOptions {
  out?: string;
  ignore?: string[];
  includeTests?: boolean;
  config?: string | false;
}

/** Records what the project has today. Returns the process exit code. */
export function runBaseline(targetPath: string, options: BaselineCommandOptions): number {
  if (!fs.existsSync(targetPath) || !fs.statSync(targetPath).isDirectory()) {
    process.stderr.write(chalk.red(`Not a folder: ${targetPath}\n`));
    return 2;
  }
  const root = path.resolve(targetPath);
  let config;
  try {
    config = options.config === false ? emptyConfig() : loadConfig(root, options.config).config;
  } catch (err) {
    if (err instanceof ConfigError) {
      process.stderr.write(chalk.red(`${err.message}\n`));
      return 2;
    }
    throw err;
  }
  const summary = scanPath(root, { ignore: options.ignore, includeTests: options.includeTests, config });
  const baseline = createBaseline(summary, root);
  if (baseline.findings.length === 0) {
    process.stdout.write(chalk.green("No findings: nothing to record. A baseline is only needed when a project already has findings.\n"));
    return 0;
  }
  const file = path.resolve(options.out ?? path.join(root, BASELINE_FILE_NAME));
  const existed = fs.existsSync(file);
  fs.writeFileSync(file, serializeBaseline(baseline), "utf8");
  process.stdout.write(
    chalk.green(`${existed ? "Updated" : "Saved"} ${baseline.findings.length} existing finding(s) in ${file}\n`) +
      "Commit this file. From now on `security-hub scan` (and the GitHub Action) report only findings that are new,\n" +
      "and say how many old ones the baseline hides. Fixing an old one makes its entry stale: run this command again to refresh.\n",
  );
  return 0;
}
