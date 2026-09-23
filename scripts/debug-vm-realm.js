// Reproduces Jest's actual isolation model: each "test file" runs in its own
// V8 context (vm.createContext), which is what jest-environment-node does.
// Requiring a native addon fresh inside each context is what we suspect breaks.
const vm = require("vm");
const Module = require("module");
const path = require("path");

function runInFreshContext(label) {
  const context = vm.createContext({ console, require, module: { exports: {} }, __dirname, __filename });
  const script = new vm.Script(`
    const Parser = require("tree-sitter");
    const JavaScript = require("tree-sitter-javascript");
    const parser = new Parser();
    parser.setLanguage(JavaScript);
    const tree = parser.parse("const x = 1;");
    console.log("${label}", "rootNode:", tree && tree.rootNode ? tree.rootNode.type : "UNDEFINED/MISSING");
  `);
  script.runInContext(context);
}

runInFreshContext("Context #1:");
runInFreshContext("Context #2:");
runInFreshContext("Context #3:");
