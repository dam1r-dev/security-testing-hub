// Builds the scanner that runs on the web page (site/scanner/): the real scanner sources bundled for the browser, with
//  - `fs`   -> an in-memory file system holding the dropped files       (packages/scanner/web/shims/fs.ts)
//  - `path` -> a POSIX path                                              (packages/scanner/web/shims/path.ts)
//  - `child_process` -> a stub (no git in a browser; the scanner falls back to .gitignore); `crypto` -> a stub (only baselines hash)
//  - the native tree-sitter parser -> web-tree-sitter, tree-sitter compiled to WebAssembly (web/browser-parser.ts)
// plus the four .wasm files it loads. Used by `npm run site:scanner` and by the Pages workflow; the same bundle can be
// built for Node (target "node") so a test can run the browser pipeline and compare it with the native scanner.
const fs = require("fs");
const path = require("path");
const { builtinModules } = require("module");
const esbuild = require("esbuild");

const root = path.resolve(__dirname, "..");
const web = path.join(root, "packages", "scanner", "web");

function packageDirectory(name) {
  return path.dirname(require.resolve(`${name}/package.json`, { paths: [root] }));
}

const WASM_FILES = [
  [path.join(packageDirectory("web-tree-sitter"), "tree-sitter.wasm"), "tree-sitter.wasm"],
  [path.join(packageDirectory("tree-sitter-javascript"), "tree-sitter-javascript.wasm"), "tree-sitter-javascript.wasm"],
  [path.join(packageDirectory("tree-sitter-typescript"), "tree-sitter-typescript.wasm"), "tree-sitter-typescript.wasm"],
  [path.join(packageDirectory("tree-sitter-typescript"), "tree-sitter-tsx.wasm"), "tree-sitter-tsx.wasm"],
  [path.join(packageDirectory("tree-sitter-python"), "tree-sitter-python.wasm"), "tree-sitter-python.wasm"],
  [path.join(packageDirectory("tree-sitter-php"), "tree-sitter-php.wasm"), "tree-sitter-php.wasm"],
];

const SHIMS = {
  fs: path.join(web, "shims", "fs.ts"),
  path: path.join(web, "shims", "path.ts"),
  child_process: path.join(web, "shims", "child-process.ts"),
  crypto: path.join(web, "shims", "crypto.ts"),
  "tree-sitter": path.join(web, "shims", "empty.ts"),
};

function swapPlugin(target) {
  const builtins = new Set([...builtinModules, ...builtinModules.map((m) => `node:${m}`)]);
  return {
    name: "swap-node-for-browser",
    setup(build) {
      // The native parser module is replaced by the WebAssembly one, wherever it is imported from.
      build.onResolve({ filter: /parsers[\\/]ast-parser$/ }, () => ({ path: path.join(web, "browser-parser.ts") }));
      build.onResolve({ filter: /^(?:node:)?[a-z_]+$|^tree-sitter$/ }, (args) => {
        const name = args.path.replace(/^node:/, "");
        if (SHIMS[name]) return { path: SHIMS[name] };
        // web-tree-sitter also contains code for running inside Node (never reached in a browser): empty modules for it.
        if (target === "browser" && builtins.has(args.path)) return { path: SHIMS["tree-sitter"] };
        return undefined;
      });
    },
  };
}

/** target "browser": site/scanner/worker.js. target "node": a CommonJS file for tests (web-tree-sitter stays external). */
async function bundle({ target, outfile }) {
  await esbuild.build({
    entryPoints: [path.join(web, target === "browser" ? "worker.ts" : "node-entry.ts")],
    outfile,
    bundle: true,
    platform: target === "browser" ? "browser" : "node",
    format: target === "browser" ? "iife" : "cjs",
    target: target === "browser" ? "es2022" : "node18",
    minify: target === "browser",
    sourcemap: false,
    legalComments: "none",
    external: target === "node" ? ["web-tree-sitter"] : [],
    define: { "process.platform": '"browser"' },
    plugins: [swapPlugin(target)],
    // index.ts also exports the `fix` command's file writing, which the page never calls: its fs functions are not in the shim
    logOverride: { "import-is-undefined": "silent" },
    logLevel: "warning",
  });
}

function copyWasm(directory) {
  fs.mkdirSync(directory, { recursive: true });
  for (const [source, name] of WASM_FILES) fs.copyFileSync(source, path.join(directory, name));
}

module.exports = { bundle, copyWasm, WASM_FILES };

if (require.main === module) {
  const out = path.join(root, "site", "scanner");
  fs.mkdirSync(out, { recursive: true });
  bundle({ target: "browser", outfile: path.join(out, "worker.js") })
    .then(() => {
      copyWasm(out);
      const size = fs.readdirSync(out).map((f) => `${f} ${(fs.statSync(path.join(out, f)).size / 1024).toFixed(0)} KB`);
      console.log(`site/scanner: ${size.join(", ")}`);
    })
    .catch((err) => {
      console.error(err.message);
      process.exit(1);
    });
}
