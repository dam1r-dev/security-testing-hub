import * as fs from "fs";
import * as path from "path";
import { spawnSync } from "child_process";
import chalk from "chalk";

// packages/cli/dist/commands/lab.js -> repo root is 4 levels up.
const REPO_ROOT = path.resolve(__dirname, "..", "..", "..", "..");
const LABS_DIR = path.join(REPO_ROOT, "labs");

const KNOWN_LABS = new Set(["sql-injection"]);

export interface LabCommandOptions {
  stop?: boolean;
}

function listAvailableLabs(): void {
  console.log("Available labs:");
  for (const name of KNOWN_LABS) {
    console.log(`  - ${name}`);
  }
  console.log("\nUsage: security-hub lab <name> [--stop]");
}

export function runLab(name: string | undefined, options: LabCommandOptions): number {
  if (!name) {
    listAvailableLabs();
    return 0;
  }

  if (!KNOWN_LABS.has(name)) {
    console.error(chalk.red(`Unknown lab "${name}".`));
    listAvailableLabs();
    return 2;
  }

  const labDir = path.join(LABS_DIR, name);
  const composeFile = path.join(labDir, "docker-compose.yml");
  if (!fs.existsSync(composeFile)) {
    console.error(chalk.red(`Lab "${name}" is missing its docker-compose.yml at ${composeFile}.`));
    return 2;
  }

  const action = options.stop ? ["down", "-v"] : ["up", "-d", "--build"];
  console.log(chalk.dim(`$ docker compose -f ${composeFile} ${action.join(" ")}`));

  const result = spawnSync("docker", ["compose", "-f", composeFile, ...action], { stdio: "inherit" });

  if (result.error) {
    console.error(chalk.red(`Could not run Docker: ${result.error.message}`));
    console.error("Is Docker installed and running?");
    return 1;
  }
  if (result.status !== 0) {
    console.error(chalk.red(`docker compose exited with code ${result.status}.`));
    return result.status ?? 1;
  }

  if (options.stop) {
    console.log(chalk.green(`Lab "${name}" stopped and cleaned up.`));
    return 0;
  }

  const readmePath = path.join(labDir, "README.md");
  console.log(chalk.green(`\nLab "${name}" is starting.`));
  console.log(`See ${readmePath} for the goal, hints, and how to verify the fix.`);
  console.log(`Stop it later with: security-hub lab ${name} --stop`);
  return 0;
}
