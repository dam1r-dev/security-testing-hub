const fs = require("fs");
const path = require("path");

// Jest gives each test FILE its own module registry, but native addons (tree-sitter here) are still loaded once per OS
// process. Re-requiring tree-sitter's native binding from a second test file inside a worker process that already
// loaded it for an earlier file produces a broken parse (rootNode ends up undefined/corrupted) -- confirmed
// reproducible in CI: with fewer workers than test files, only the first file each worker picks up passes;
// --runInBand (1 worker) only passes the very first file overall. A worker count above the number of test files gives
// every file its own fresh process instead of reusing a worker, which sidesteps the bug entirely.
//
// The number of files grows, so it is counted instead of hard-coded: a fixed 32 silently stopped being enough at the
// 33rd file, and the symptom was random "Cannot read properties of undefined" failures in unrelated suites.
const testFiles = fs.readdirSync(path.join(__dirname, "tests")).filter((name) => name.endsWith(".test.ts")).length;

/** @type {import('jest').Config} */
module.exports = {
  preset: "ts-jest",
  testEnvironment: "node",
  testMatch: ["<rootDir>/tests/**/*.test.ts"],
  maxWorkers: testFiles + 2,
};
