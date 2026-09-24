/** @type {import('jest').Config} */
module.exports = {
  preset: "ts-jest",
  testEnvironment: "node",
  testMatch: ["<rootDir>/tests/**/*.test.ts"],
  // See packages/scanner/jest.config.js for why: this package imports
  // security-hub-scanner, which loads tree-sitter's native binding.
  maxWorkers: 32,
};
