# The scanner in the browser

The website ([dam1r-dev.github.io/security-testing-hub](https://dam1r-dev.github.io/security-testing-hub/)) can scan a
project folder without installing anything: drop the folder on the page (or press *Choose a folder*).

**Your code does not leave your computer.** The page reads the files itself and hands them to a Web Worker that runs
the scanner; the only things it downloads are the scanner's own files from the same site (`scanner/worker.js`, about
210 KB, and the WebAssembly parser: 186 KB for the runtime plus a grammar per language the project uses: JavaScript
350 KB, TypeScript and TSX 1.4 MB each). The page's Content-Security-Policy allows nothing else.

## How it works

It is not a second implementation of the rules. `scripts/build-site-scanner.js` bundles the real scanner sources
(`packages/scanner/src`) for the browser and swaps four things:

| Node | In the browser |
|---|---|
| `fs` | an in-memory, read-only file system holding the dropped files (`packages/scanner/web/shims/fs.ts`); `scanPath` and every check that looks at `.env`, Supabase SQL, Firebase rules, `package.json` or public folders run on it unchanged |
| `path` | a POSIX `path` (`web/shims/path.ts`), tested against Node's on a long list of inputs |
| `child_process` (git) | a stub that fails; the scanner already falls back to `.gitignore` when git is not available |
| the native tree-sitter addon | `web-tree-sitter`, tree-sitter compiled to WebAssembly, with the same grammars (`web/browser-parser.ts`) |

Because it is one code path, results are the same. `tests/web-parity.test.ts` builds the bundle and compares every
finding (file, line, rule, severity, confidence, message) with the native scanner on the four example projects and on a
project with cross-file data flow, `.env`, Supabase and Firebase files; before the feature was merged the same
comparison was run on 30 real repositories (the validation corpora): identical on all of them. The WebAssembly build was
also faster than the native one in that comparison (the native parser pays for a forced garbage collection after every
file; see `parsers/gc-workaround.ts`).

Hostile files are handled like on the command line: a 20 s parse limit, a 15 s analysis budget per file, and a cap on
secret findings (`docs/security-audit.md`); a file that cannot be finished is listed in the page's notes, never shown as clean.

## What it does not do

- **No git**: whether a `.env` file is committed or ignored is decided from `.gitignore` only.
- **No `--audit`** (known-vulnerable dependencies need npm's advisory database, a network call) and no `fix --write`
  (the page cannot change your files; copy the fix prompt into your AI assistant, or use the command line).
- **Skipped on purpose:** `node_modules`, `.git` (only its presence is kept: a served `.git` folder is still reported),
  build output, lock files; images, fonts and archives are listed by name but never read; files over 2 MB are skipped
  with a note; at most 30 000 files and 200 MB of text are read, and the page says so when a folder is larger.
- A browser that does not support `webkitdirectory` / Web Workers, or the page opened from a `file://` address, shows a
  message and the command to run instead (`npx security-hub scan .`).

## Working on it

```bash
npm run site:scanner   # builds site/scanner/ (worker.js + the four .wasm files; not committed)
npm run site:serve     # http://127.0.0.1:4173/ (a Web Worker does not start from file://)
npm run typecheck:web -w security-hub-scanner
```

After editing the script in `site/index.html`, run `node scripts/update-site-csp.js` (the policy allows that one inline
script by its hash).
