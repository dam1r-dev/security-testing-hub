// The browser cannot start programs. The scanner only uses git to learn whether a file is committed or ignored, and it
// already handles "git is not available" by reading .gitignore instead, so a failing call is exactly the right answer.
export function execFileSync(): never {
  throw new Error("Running programs is not possible in the browser.");
}
