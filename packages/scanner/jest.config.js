/** @type {import('jest').Config} */
module.exports = {
  preset: "ts-jest",
  testEnvironment: "node",
  testMatch: ["<rootDir>/tests/**/*.test.ts"],
  // Jest gives each test FILE its own module registry, but native addons
  // (tree-sitter here) are still loaded once per OS process. Re-requiring
  // tree-sitter's native binding from a second test file inside a worker
  // process that already loaded it for an earlier file produces a broken
  // parse (rootNode ends up undefined/corrupted) — confirmed reproducible
  // in CI: with fewer workers than test files, only the first file each
  // worker picks up passes; --runInBand (1 worker) only passes the very
  // first file overall. A generous maxWorkers (comfortably above the
  // current test file count) gives every file its own fresh process
  // instead of reusing a worker, which sidesteps the bug entirely.
  maxWorkers: 32,
};
