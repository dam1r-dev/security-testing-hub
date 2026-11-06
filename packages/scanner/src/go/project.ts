import * as fs from "fs";
import * as path from "path";
import { checkBudgetNow } from "../budget";
import { ParsedFile, parseFile } from "../parsers/ast-parser";
import { SyntaxNode, findNodes } from "../parsers/utils";
import { ProjectContext } from "../taint/project";
import { NO_ROOTS, calleeText, callArguments, carriedBy, rootsOf, trackTaint } from "./engine";
import { SinkSpec, sinksOf } from "./sinks";

/**
 * What the rest of the project does with a value handed to it. A handler calls `repo.FindUser(name)`; the SQL is built in another file.
 * The index finds the function by name (the one in the same folder first, then the only one in the project), works out which parameters
 * of it reach a dangerous call (following calls to other helpers up to three deep), and reports the finding at the call in the handler,
 * naming the place the value ends up. A name that more than one function carries (an interface and its implementations, `Get`, `Close`)
 * is not followed: the scanner cannot tell which one runs. Reads other files through `fs`, so the same code runs in the browser build.
 */

const MAX_FILE_BYTES = 1024 * 1024;
const MAX_FILES = 6000;
const MAX_DEPTH = 3;
const SKIPPED_DIRECTORIES = new Set(["vendor", "node_modules", ".git", "testdata", "third_party", "dist", "build", ".idea", ".vscode"]);

export interface Hit {
  spec: SinkSpec;
  /** Where the dangerous call is. */
  file: string;
  line: number;
  /** The helpers the value went through, outermost first. */
  chain: string[];
}

export interface FunctionRef {
  file: string;
  fn: SyntaxNode;
  name: string;
}

// Names too general to say which function a call means.
const COMMON = new Set([
  "get", "set", "add", "remove", "delete", "update", "create", "find", "list", "save", "load", "close", "open", "read", "write", "run", "start", "stop",
  "init", "new", "handle", "serve", "servehttp", "string", "error", "len", "less", "swap", "exec", "query", "do", "call", "send", "put", "post", "patch",
  "head", "next", "reset", "clear", "count", "all", "one", "first", "last", "print", "printf", "println", "log", "logf", "info", "warn", "debug", "fatal",
  "panic", "wait", "done", "flush", "sync", "lock", "unlock", "register", "use", "route", "group", "bind", "render", "json", "xml", "html", "text",
  "param", "params", "query", "form", "header", "headers", "cookie", "body", "status", "abort", "next", "redirect", "file", "data", "value", "name",
  "marshal", "unmarshal", "encode", "decode", "parse", "format", "validate", "check", "process", "execute", "apply", "build", "make", "wrap", "unwrap",
]);

const DEFINITION = /^func\s+(?:\([^)]*\)\s*)?([A-Za-z_]\w*)\s*[[(]/gm;

export class GoProject {
  private static readonly instances = new WeakMap<ProjectContext, GoProject>();
  private readonly parsed = new Map<string, ParsedFile | null>();
  private definitions: Map<string, string[]> | undefined;
  private readonly summaries = new Map<string, Map<number, Hit>>();
  private readonly inProgress = new Set<string>();

  private constructor(readonly context: ProjectContext) {}

  static of(context: ProjectContext): GoProject {
    let project = GoProject.instances.get(context);
    if (!project) {
      project = new GoProject(context);
      GoProject.instances.set(context, project);
    }
    return project;
  }

  /** The tree of `file`: the one the scan already holds, or a parse read from disk (remembered, and handed back to the scan). */
  parse(file: string, known?: ParsedFile): ParsedFile | undefined {
    const key = path.resolve(file);
    if (known) this.parsed.set(key, known);
    const cached = this.parsed.get(key);
    if (cached !== undefined) return cached ?? undefined;
    let result: ParsedFile | undefined;
    try {
      const size = fs.statSync(key).size;
      if (size <= MAX_FILE_BYTES) result = parseFile(key, fs.readFileSync(key, "utf8"));
    } catch {
      result = undefined;
    }
    this.parsed.set(key, result ?? null);
    if (result) this.context.fileInfo(key, result); // the scan reaches this file later and reuses the parse
    return result;
  }

  /** Function and method names -> the files that declare one. Built once from the text of the project's `.go` files. */
  private index(): Map<string, string[]> {
    if (this.definitions) return this.definitions;
    const map = new Map<string, string[]>();
    this.definitions = map;
    let files = 0;
    const visit = (dir: string, depth: number): void => {
      if (files >= MAX_FILES || depth > 14) return;
      let entries: fs.Dirent[];
      try {
        entries = fs.readdirSync(dir, { withFileTypes: true }) as fs.Dirent[];
      } catch {
        return;
      }
      for (const entry of entries) {
        const full = path.join(dir, entry.name);
        if (entry.isDirectory()) {
          if (!SKIPPED_DIRECTORIES.has(entry.name) && !entry.name.startsWith(".")) visit(full, depth + 1);
        } else if (entry.name.endsWith(".go") && !entry.name.endsWith("_test.go")) {
          files++;
          if (files > MAX_FILES) return;
          let text: string;
          try {
            if (fs.statSync(full).size > MAX_FILE_BYTES) continue;
            text = fs.readFileSync(full, "utf8");
          } catch {
            continue;
          }
          for (const match of text.matchAll(DEFINITION)) {
            const name = match[1] as string;
            const list = map.get(name);
            if (!list) map.set(name, [full]);
            else if (!list.includes(full)) list.push(full);
          }
        }
      }
    };
    visit(this.context.root, 0);
    return map;
  }

  /** The declarations called `name` in `file`. */
  private declarationsIn(file: string, name: string): SyntaxNode[] {
    const parsed = this.parse(file);
    if (!parsed) return [];
    return parsed.tree.rootNode.namedChildren.filter((n) => (n.type === "function_declaration" || n.type === "method_declaration") && n.childForFieldName("name")?.text === name);
  }

  /** The function a call means, when that is certain: declared in this file, else in this folder, else the only one of its name in the project. */
  resolve(call: SyntaxNode, fromFile: string): FunctionRef | undefined {
    const callee = call.childForFieldName("function");
    if (!callee) return undefined;
    const name = callee.type === "identifier" ? callee.text : callee.type === "selector_expression" ? callee.childForFieldName("field")?.text : undefined;
    if (!name || COMMON.has(name.toLowerCase())) return undefined;
    const files = this.index().get(name);
    if (!files || files.length === 0) return undefined;
    const from = path.resolve(fromFile);
    let chosen: string | undefined;
    if (callee.type === "identifier") {
      // same package: every file of the folder
      const sameFolder = files.filter((f) => path.dirname(f) === path.dirname(from));
      if (sameFolder.length === 1) chosen = sameFolder[0];
      else if (sameFolder.length === 0 && files.length === 1) chosen = files[0];
    } else if (files.length === 1) {
      chosen = files[0];
    }
    if (!chosen) return undefined;
    const found = this.declarationsIn(chosen, name);
    // two declarations of one name in a file (methods of different types): not told apart
    if (found.length !== 1) return undefined;
    const declaration = found[0];
    if (!declaration) return undefined;
    // a method call must hit a method, a package function call a function; a name used both ways is not followed
    const isMethod = declaration.type === "method_declaration";
    if (callee.type === "identifier" && isMethod) return undefined;
    return { file: chosen, fn: declaration, name };
  }

  /** The names of a function's parameters, in order (`func f(a, b string, c int)` -> a, b, c; the receiver is not one). */
  parameterNames(fn: SyntaxNode): string[] {
    const names: string[] = [];
    for (const declaration of fn.childForFieldName("parameters")?.namedChildren ?? []) {
      if (declaration.type !== "parameter_declaration" && declaration.type !== "variadic_parameter_declaration") continue;
      const own = declaration.namedChildren.filter((c) => c.type === "identifier");
      if (own.length === 0) names.push("_"); // an unnamed parameter still takes an argument
      else for (const n of own) names.push(n.text);
    }
    return names;
  }

  /** For each parameter of `ref` (by position) that reaches a dangerous call: the first place it does. */
  summary(ref: FunctionRef, depth = 0): Map<number, Hit> {
    const key = `${ref.file}:${ref.fn.startIndex}`;
    const known = this.summaries.get(key);
    if (known) return known;
    const result = new Map<number, Hit>();
    if (depth > MAX_DEPTH || this.inProgress.has(key)) return result;
    this.inProgress.add(key);
    const parsed = this.parse(ref.file);
    const names = this.parameterNames(ref.fn);
    const roots = rootsOf(ref.fn);
    // a function that reads the request itself is a handler, not a helper: its own findings are reported there
    if (parsed && roots.requests.size === 0 && roots.contexts.size === 0) {
      names.forEach((name, index) => {
        if (name === "_" || result.has(index)) return;
        checkBudgetNow();
        trackTaint(ref.fn, NO_ROOTS, new Set([name]), {
          onCall: (call, tainted) => {
            if (result.has(index)) return;
            for (const spec of sinksOf(call, NO_ROOTS)) {
              const via = spec.args.map((arg) => carriedBy(arg, tainted, NO_ROOTS)).find((v) => v !== undefined);
              if (via === undefined) continue;
              result.set(index, { spec, file: ref.file, line: call.startPosition.row + 1, chain: [] });
              return;
            }
            // one more helper deeper
            const next = this.resolve(call, ref.file);
            if (!next || next.fn.id === ref.fn.id && next.file === ref.file) return;
            for (const [position, hit] of this.summary(next, depth + 1)) {
              const arg = callArguments(call)[position];
              if (!arg || carriedBy(arg, tainted, NO_ROOTS) === undefined) continue;
              result.set(index, { ...hit, chain: [next.name, ...hit.chain] });
              return;
            }
          },
        });
      });
    }
    this.inProgress.delete(key);
    if (depth === 0) this.summaries.set(key, result);
    return result;
  }
}

/** The calls inside a function (for callers that need them without a walk). */
export function callsIn(fn: SyntaxNode): SyntaxNode[] {
  return findNodes(fn, (n) => n.type === "call_expression");
}

export { calleeText };
