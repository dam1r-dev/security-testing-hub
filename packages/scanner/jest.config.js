/** @type {import('jest').Config} */
module.exports = {
  preset: "ts-jest",
  testEnvironment: "node",
  testMatch: ["<rootDir>/tests/**/*.test.ts"],
  // No special worker count is needed. This used to be `maxWorkers: 32`, because a second test file in a worker process
  // got a broken parser (the native tree-sitter addon was loaded again by the next test file's module registry, and
  // parse results came back without a rootNode): the suite only worked while every file had a process of its own, and it
  // started failing at random when the 33rd file was added. src/parsers/ast-parser.ts now loads the addon once per
  // process and shares it, so any number of files can run in one worker (`jest --runInBand` passes).
};
