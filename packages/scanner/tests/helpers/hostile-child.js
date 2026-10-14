// Runs ONE hostile input through the built scanner (dist/) in its own process and prints what happened as JSON.
// Used by tests/hostile-input.test.ts: a 60 000-deep tree is exactly the kind of input that must not share a process with
// the other tests (inside a jest worker it leaves node-tree-sitter's shared state in a bad way for the suites that run
// after it; in a plain process it does not, which is how the scanner itself runs).
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
