/**
 * How this project runs `git` inside a folder it does not own.
 *
 * A scan can be pointed at a folder somebody else made (an unpacked archive, a downloaded project), and git reads a
 * repository's own config: `core.fsmonitor` is a command git runs on `status` / `diff` / `ls-files`. Every git call the
 * scanner makes is read-only, so it switches those hooks off and asks git not to touch the repository (no index
 * refresh, no lock files, no prompts).
 */

/** Put these before the git sub-command: `git <GIT_HARDENING_ARGS> status ...`. */
export const GIT_HARDENING_ARGS: readonly string[] = ["-c", "core.fsmonitor=false", "-c", "core.untrackedCache=false", "-c", "protocol.ext.allow=never"];

/** The environment for those calls. */
export function gitEnvironment(): NodeJS.ProcessEnv {
  return { ...process.env, GIT_OPTIONAL_LOCKS: "0", GIT_TERMINAL_PROMPT: "0" };
}
