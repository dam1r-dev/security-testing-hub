// Simulates what Jest does between test files: delete the require cache
// entries for tree-sitter and re-require them fresh, then try parsing again.
const path = require("path");

function resolveInto(pkg) {
  return require.resolve(pkg);
}

function parseOnce(label) {
  const Parser = require("tree-sitter");
  const JavaScript = require("tree-sitter-javascript");
  const parser = new Parser();
  parser.setLanguage(JavaScript);
  const tree = parser.parse("const x = 1;");
  console.log(label, "rootNode:", tree && tree.rootNode ? tree.rootNode.type : "UNDEFINED/MISSING");
}

parseOnce("First parse (fresh require):");

// Simulate Jest's per-test-file module registry reset for these packages
// (and everything they pulled in) by wiping them from require.cache.
for (const key of Object.keys(require.cache)) {
  if (/tree-sitter/.test(key)) {
    delete require.cache[key];
  }
}

parseOnce("Second parse (after deleting require.cache entries):");
