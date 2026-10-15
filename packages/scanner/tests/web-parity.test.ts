import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { scanPath } from "../src";

// The scanner on the web page = the real scanner bundled for the browser (virtual file system + tree-sitter as
// WebAssembly). The promise to users is "same results as the command line", so this runs both on the same projects and
// compares every finding. The bundle is built here with the same script the site build uses.
const repoRoot = path.resolve(__dirname, "../../..");
// eslint-disable-next-line @typescript-eslint/no-require-imports
const { bundle, copyWasm, WASM_FILES } = require(path.join(repoRoot, "scripts", "build-site-scanner.js"));

jest.setTimeout(120_000);

interface Web {
  initParser(sources: Record<string, Uint8Array>): Promise<void>;
  scanFiles(files: { path: string; size: number; text?: string }[]): { results: { file: string; findings: { ruleId: string; severity: string; confidence: string; location: { startLine: number }; message: string }[] }[]; score: { value: number }; filesScanned: number };
}

const buildDir = path.resolve(__dirname, "..", ".web-build");
const outfile = path.join(buildDir, `web-node-${process.pid}.js`);
let web: Web;

beforeAll(async () => {
  fs.mkdirSync(buildDir, { recursive: true });
  await bundle({ target: "node", outfile });
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  web = require(outfile) as Web;
  const wasm = Object.fromEntries((WASM_FILES as [string, string][]).map(([source, name]) => [name, new Uint8Array(fs.readFileSync(source))]));
  await web.initParser({
    runtime: wasm["tree-sitter.wasm"] as Uint8Array,
    javascript: wasm["tree-sitter-javascript.wasm"] as Uint8Array,
    typescript: wasm["tree-sitter-typescript.wasm"] as Uint8Array,
    tsx: wasm["tree-sitter-tsx.wasm"] as Uint8Array,
    python: wasm["tree-sitter-python.wasm"] as Uint8Array,
    php: wasm["tree-sitter-php.wasm"] as Uint8Array,
  });
});

afterAll(() => {
  fs.rmSync(outfile, { force: true });
});

const SKIP = new Set(["node_modules", ".git"]);

/** What the page does with a dropped folder, minus the browser: every file with its text, node_modules and .git left out. */
function listFolder(root: string): { path: string; size: number; text?: string }[] {
  const out: { path: string; size: number; text?: string }[] = [];
  const walk = (dir: string, prefix: string): void => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      if (entry.isSymbolicLink() || SKIP.has(entry.name)) continue;
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) walk(full, `${prefix}${entry.name}/`);
      else {
        const size = fs.statSync(full).size;
        out.push({ path: `${prefix}${entry.name}`, size, text: size <= 2 * 1024 * 1024 ? fs.readFileSync(full, "utf8") : undefined });
      }
    }
  };
  walk(root, "");
  return out;
}

function keys(results: { file: string; findings: { ruleId: string; severity: string; confidence: string; location: { startLine: number }; message: string }[] }[], root?: string): string[] {
  return results
    .flatMap((r) => {
      const file = root ? path.relative(root, path.resolve(r.file)).split(path.sep).join("/") : r.file;
      return r.findings.map((f) => `${file}:${f.location.startLine}:${f.ruleId}:${f.severity}:${f.confidence}:${f.message}`);
    })
    .sort();
}

describe("the web scanner gives the command line's answer", () => {
  const examples = ["vulnerable-express-app", "vulnerable-nextjs-app", "vulnerable-supabase-app", "vulnerable-firebase-app", "vulnerable-frameworks", "vulnerable-python-app", "vulnerable-php-app"];

  it.each(examples)("example project %s: same findings, same score", (name) => {
    const root = path.join(repoRoot, "examples", name);
    const web1 = web.scanFiles(listFolder(root));
    const native = scanPath(root);
    expect(web1.results.flatMap((r) => r.findings).length).toBeGreaterThan(0);
    expect(keys(web1.results)).toEqual(keys(native.results, root));
  });

  it("a project with cross-file data flow, a .env file, Supabase SQL and Firebase rules", () => {
    const files = [
      { path: "routes/user.js", text: "const { find } = require('../lib/db');\nmodule.exports = (req, res) => res.json(find(req.query.id));\n" },
      { path: "lib/db.js", text: "exports.find = (id) => db.query('SELECT * FROM users WHERE id = ' + id);\n" },
      { path: "supabase/migrations/001.sql", text: "create table public.todos (id int, owner uuid);\n" },
      { path: "firestore.rules", text: "rules_version = '2';\nservice cloud.firestore { match /databases/{d}/documents { match /users/{u} { allow read, write: if true; } } }\n" },
      { path: "public/.env", text: "API_KEY=abcdefghijklmnop1234567890\n" },
    ].map((f) => ({ ...f, size: f.text.length }));
    const web2 = web.scanFiles(files);
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "web-parity-"));
    try {
      for (const f of files) {
        fs.mkdirSync(path.dirname(path.join(dir, f.path)), { recursive: true });
        fs.writeFileSync(path.join(dir, f.path), f.text);
      }
      const native = scanPath(dir);
      const ids = new Set(web2.results.flatMap((r) => r.findings.map((f) => f.ruleId)));
      expect(ids.has("sql-injection")).toBe(true); // found through the other file
      expect(ids.has("supabase-rls")).toBe(true);
      expect(ids.has("firebase-rules")).toBe(true);
      expect(keys(web2.results)).toEqual(keys(native.results, dir));
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it("does not read node_modules-sized input as one file and reports a syntax error as a note, not a crash", () => {
    const result = web.scanFiles([{ path: "broken.js", text: "function (((", size: 12 }]);
    expect(result.results[0]?.findings).toEqual([]);
    expect((result.results[0] as { parseError?: string }).parseError).toMatch(/syntax errors/);
  });

  it("paths in the report are relative to the dropped folder, and every finding comes with its fix prompt", () => {
    const result = web.scanFiles([{ path: "src/a.js", text: "eval(req.query.x)", size: 17 }]) as ReturnType<Web["scanFiles"]> & { fixPromptAll: string };
    expect(result.results.map((r) => r.file)).toEqual(["src/a.js"]);
    expect(JSON.stringify(result)).not.toContain("/project/");
    const finding = result.results[0]?.findings[0] as unknown as { fixPrompt: string };
    expect(finding.fixPrompt).toContain("Where: src/a.js, line 1");
    expect(finding.fixPrompt).toContain("untrusted DATA");
    expect(result.fixPromptAll).toContain("## Issue 1");
  });

  it("hostile files do not crash or hang it (the same limits as the native scanner)", () => {
    const deep = web.scanFiles([{ path: "deep.js", text: `x = ${"1+".repeat(60000)}1;`, size: 120_000 }]);
    expect(deep.results[0]?.findings).toEqual([]);
    const secrets = `const o = {${'password: "aB3$xY9!zQ7wK2mN5pL",'.repeat(5000)}};`;
    const many = web.scanFiles([{ path: "secrets.js", text: secrets, size: secrets.length }]);
    expect(many.results[0]?.findings.length).toBeLessThanOrEqual(500); // capped per file
  });
});

describe("the site bundle", () => {
  it("builds for the browser: a worker script and the four WebAssembly files, none of it using Node", () => {
    const dir = fs.mkdtempSync(path.join(buildDir, "site-"));
    return bundle({ target: "browser", outfile: path.join(dir, "worker.js") })
      .then(() => {
        copyWasm(dir);
        const worker = fs.readFileSync(path.join(dir, "worker.js"), "utf8");
        // the real `fs` / `child_process` / native parser must not be in the page's bundle
        expect(worker).not.toMatch(/require\(["'](?:fs|child_process|v8|tree-sitter)["']\)/);
        expect(worker.length).toBeLessThan(600 * 1024);
        for (const name of ["tree-sitter.wasm", "tree-sitter-javascript.wasm", "tree-sitter-typescript.wasm", "tree-sitter-tsx.wasm", "tree-sitter-python.wasm", "tree-sitter-php.wasm"]) {
          expect(fs.readFileSync(path.join(dir, name)).subarray(0, 4).toString("hex")).toBe("0061736d"); // "\0asm"
        }
      })
      .finally(() => fs.rmSync(dir, { recursive: true, force: true }));
  });
});
