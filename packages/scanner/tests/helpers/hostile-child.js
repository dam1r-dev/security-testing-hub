// Runs ONE hostile input through the built scanner (dist/) in its own process and prints what happened as JSON.
// Used by tests/hostile-input.test.ts: inputs that need hundreds of megabytes and many seconds are kept out of the test
// runner's own processes, and this is how the scanner really runs: a fresh process, built code.
const path = require("path");

const dist = path.resolve(__dirname, "..", "..", "dist", "index.js");
const { scanSource, defaultAnalyzers } = require(dist);

const cases = {
  "deep-expression": () => "x = " + "1+".repeat(60000) + "1;",
  "member-chain": () => "x = a" + ".b".repeat(30000) + ";",
  parentheses: () => "x = " + "(".repeat(3000) + "1" + ")".repeat(3000) + ";",
  "many-secrets": () => "const o = {" + 'password: "aB3$xY9!zQ7wK2mN5pL",'.repeat(5000) + "};",
};

const text = cases[process.argv[2]]();
const started = Date.now();
let outcome;
try {
  const result = scanSource(text, "hostile.js", defaultAnalyzers());
  outcome = {
    threw: false,
    ms: Date.now() - started,
    secretFindings: result.findings.filter((f) => f.ruleId === "hardcoded-secret").length,
    note: result.parseError || "",
  };
} catch (err) {
  outcome = { threw: true, ms: Date.now() - started, message: String(err && err.message) };
}
process.stdout.write(JSON.stringify(outcome));
