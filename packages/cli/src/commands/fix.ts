import { execFileSync } from "child_process";
import * as fs from "fs";
import * as path from "path";
import chalk from "chalk";
import { FIXABLE_RULES, FixPlan, GIT_HARDENING_ARGS, applyPlan, gitEnvironment, planFixes, renderPlan, scanPath } from "security-hub-scanner";

export interface FixCommandOptions {
  /** Actually change files (default: only show what would change). */
  write?: boolean;
  /** Fix only these rules. */
  only?: string[];
  /** Change files even when git shows uncommitted edits in them. */
  force?: boolean;
  ignore?: string[];
  includeTests?: boolean;
}

type Out = (line: string) => void;

function git(cwd: string, args: string[]): { ok: boolean; out: string } {
  try {
    return { ok: true, out: execFileSync("git", [...GIT_HARDENING_ARGS, ...args], { cwd, stdio: ["ignore", "pipe", "ignore"], timeout: 15000, env: gitEnvironment() }).toString() };
  } catch {
    return { ok: false, out: "" };
  }
}

/** Files of the plan that git says have uncommitted changes; `undefined` when the folder is not a git repository. */
function dirtyFiles(files: string[], root: string): string[] | undefined {
  const inside = git(root, ["rev-parse", "--is-inside-work-tree"]);
  if (!inside.ok) return undefined;
  const dirty: string[] = [];
  for (const file of files) {
    if (!fs.existsSync(file)) continue;
    const status = git(path.dirname(file), ["status", "--porcelain", "--", path.basename(file)]);
    if (status.ok && status.out.trim() !== "") dirty.push(file);
  }
  return dirty;
}

function planFiles(plan: FixPlan): string[] {
  return [...new Set([...plan.edits.map((e) => e.file), ...plan.writes.map((w) => w.file)])];
}

function countFixable(summary: ReturnType<typeof scanPath>, only?: string[]): number {
  const rules = new Set<string>(only ?? FIXABLE_RULES);
  return summary.results.flatMap((r) => r.findings).filter((f) => rules.has(f.ruleId)).length;
}

function colorDiff(diff: string): string {
  return diff
    .split("\n")
    .map((line) => (line.startsWith("+++") || line.startsWith("---") ? chalk.bold(line) : line.startsWith("@@") ? chalk.cyan(line) : line.startsWith("+") ? chalk.green(line) : line.startsWith("-") ? chalk.red(line) : line))
    .join("\n");
}

export function runFix(targetPath: string, options: FixCommandOptions = {}, out: Out = console.log): number {
  const resolved = path.resolve(targetPath);
  if (!fs.existsSync(resolved)) {
    console.error(chalk.red(`Path not found: ${targetPath}`));
    return 2;
  }
  const root = fs.statSync(resolved).isDirectory() ? resolved : path.dirname(resolved);
  const unknown = (options.only ?? []).filter((rule) => !(FIXABLE_RULES as readonly string[]).includes(rule));
  if (unknown.length > 0) {
    console.error(chalk.red(`No automatic fix for: ${unknown.join(", ")}. Rules that can be fixed: ${FIXABLE_RULES.join(", ")}`));
    return 2;
  }

  const scan = (): ReturnType<typeof scanPath> => scanPath(root, { ignore: options.ignore, includeTests: options.includeTests });
  const before = scan();
  const plan = planFixes(before, root, { only: options.only });
  const files = planFiles(plan);

  const printLeftovers = (): void => {
    if (plan.skipped.length > 0) {
      out("");
      out(chalk.yellow(`Left for you (${plan.skipped.length}): a fix here would not be safe to do automatically`));
      for (const { finding, reason } of plan.skipped) {
        const where = `${path.relative(root, finding.location.file).split(path.sep).join("/")}:${finding.location.startLine}`;
        out(`  ${finding.ruleId}  ${where}: ${reason}`);
      }
    }
    if (plan.manual > 0) out(chalk.gray(`${plan.manual} other finding(s) have no automatic fix: run \`security-hub scan ${targetPath} --format prompt\` for a prompt to give your AI assistant.`));
  };

  if (files.length === 0) {
    out(chalk.green("Nothing to fix automatically."));
    printLeftovers();
    return 0;
  }

  out(renderPlan(plan, root).split("\n").map((l) => (l.startsWith("  # ") ? chalk.gray(l) : colorDiff(l))).join("\n"));
  out(chalk.bold(`${plan.edits.length + plan.writes.length} change(s) in ${files.length} file(s).`));
  for (const item of plan.todo) out(`${chalk.yellow("TODO")} ${item}`);
  printLeftovers();

  if (!options.write) {
    out("");
    out(chalk.bold("Nothing was changed. Run the same command with --write to apply this."));
    return 0;
  }

  const dirty = dirtyFiles(files, root);
  if (dirty && dirty.length > 0 && !options.force) {
    console.error(chalk.red(`\nRefusing to change files with uncommitted edits, so you can always see exactly what the fixer did with \`git diff\`:`));
    for (const file of dirty) console.error(`  ${path.relative(root, file)}`);
    console.error("Commit or stash them first, or run again with --force.");
    return 1;
  }
  const noGit = dirty === undefined;
  const result = applyPlan(plan, { backup: noGit, root });
  out("");
  out(chalk.green(`Changed ${result.changed.length} file(s).`));
  if (noGit) out(chalk.gray(`This folder is not a git repository, so each changed file was copied to <name>.security-hub.bak first (${result.backups.length} backup(s)).`));
  else out(chalk.gray("Review it with `git diff`; undo it with `git checkout -- .` (new files: delete them)."));

  const after = scan();
  const left = countFixable(after, options.only);
  const was = countFixable(before, options.only);
  out(`${chalk.bold("Findings the fixer handles:")} ${was} -> ${left}`);
  return 0;
}
