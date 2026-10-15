// The page never creates a baseline (that is a command line job), but the scanner's code that does is part of the same
// bundle. Hashing is not available there, so a call fails loudly instead of returning something wrong.
export function createHash(): never {
  throw new Error("Hashing is not available in the browser build.");
}
