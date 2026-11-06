import * as fs from "fs";
import * as path from "path";
import { checkBudgetNow } from "../budget";
import { ParsedFile, parseFile } from "../parsers/ast-parser";
import { SyntaxNode } from "../parsers/utils";
import { ProjectContext } from "../taint/project";
import { NO_ROOTS, argumentsOf, callInfo, carriedBy, hasRoots, rootsOf, trackTaint } from "./engine";
import { SinkSpec, sinksOf } from "./sinks";

/**
 * What the rest of the project does with a value handed to it. A controller calls `userService.findByName(name)`; the SQL is built in the
 * service. The index finds the method by name (the one in the same file first, then the only one in the project, told apart by the number of
 * arguments), works out which parameters of it reach a dangerous call (following calls to other methods up to three deep), and reports the
 * finding at the call in the controller, naming the place the value ends up. A name that more than one method carries (an interface method
 * has no body and is not counted: the implementation is) is not followed: the scanner cannot tell which one runs. Reads other files through
 * `fs`, so the same code runs in the browser build.
 */

const MAX_FILE_BYTES = 1024 * 1024;
const MAX_FILES = 6000;
const MAX_DEPTH = 3;
const SKIPPED_DIRECTORIES = new Set(["node_modules", ".git", "target", "build", ".gradle", ".idea", ".mvn", "generated", "generated-sources", "out", "bin", ".vscode"]);
const TEST_FILE = /(?:Tests?|IT|Spec)\.java$/;

export interface Hit {
  spec: SinkSpec;
  file: string;
  line: number;
  /** The helpers the value went through, outermost first. */
  chain: string[];
}

export interface MethodRef {
  file: string;
  fn: SyntaxNode;
  name: string;
}

// Names too general to say which method a call means.
const COMMON = new Set([
  "get", "set", "add", "remove", "delete", "update", "create", "find", "list", "save", "load", "close", "open", "read", "write", "run", "start", "stop",
  "init", "handle", "string", "tostring", "equals", "hashcode", "size", "length", "execute", "query", "call", "send", "put", "post", "next", "reset",
  "clear", "count", "all", "one", "first", "last", "print", "println", "log", "info", "warn", "debug", "error", "wait", "flush", "apply", "accept",
  "test", "build", "make", "wrap", "parse", "format", "validate", "check", "process", "contains", "map", "filter", "stream", "of", "from", "to", "with",
  "getid", "getname", "setname", "setid", "getvalue", "setvalue", "findbyid", "findall", "getall", "existsbyid", "deletebyid", "main", "doget", "dopost",
]);
const KEYWORD = new Set(["if", "for", "while", "switch", "catch", "new", "return", "else", "synchronized", "throw", "super", "this", "try", "do", "case", "assert", "instanceof"]);
const DEFINITION = /^\s*(?:@\w+(?:\([^)]*\))?\s+)*(?:(?:public|protected|private|static|final|synchronized|abstract|default)\s+)*(?:<[^>]+>\s+)?[\w.<>[\],?]+\s+(\w+)\s*\(/;

export class JavaProject {
  private static readonly instances = new WeakMap<ProjectContext, JavaProject>();
  private readonly parsed = new Map<string, ParsedFile | null>();
  private definitions: Map<string, string[]> | undefined;
  private readonly summaries = new Map<string, Map<number, Hit>>();
  private readonly inProgress = new Set<string>();

  private constructor(readonly context: ProjectContext) {}

  static of(context: ProjectContext): JavaProject {
    let project = JavaProject.instances.get(context);
    if (!project) {
      project = new JavaProject(context);
      JavaProject.instances.set(context, project);
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

  /** Method names -> the files that may declare one. Built once from the text of the project's `.java` files (confirmed by parsing when used). */
  private index(): Map<string, string[]> {
    if (this.definitions) return this.definitions;
    const map = new Map<string, string[]>();
    this.definitions = map;
    let files = 0;
    const visit = (dir: string, depth: number): void => {
      if (files >= MAX_FILES || depth > 16) return;
      let entries: fs.Dirent[];
      try {
        entries = fs.readdirSync(dir, { withFileTypes: true }) as fs.Dirent[];
      } catch {
        return;
      }
      for (const entry of entries) {
        const full = path.join(dir, entry.name);
        if (entry.isDirectory()) {
          if (!SKIPPED_DIRECTORIES.has(entry.name) && !entry.name.startsWith(".") && !(entry.name === "test" && path.basename(dir) === "src")) visit(full, depth + 1);
        } else if (entry.name.endsWith(".java") && !TEST_FILE.test(entry.name)) {
          files++;
          if (files > MAX_FILES) return;
          let text: string;
          try {
            if (fs.statSync(full).size > MAX_FILE_BYTES) continue;
            text = fs.readFileSync(full, "utf8");
          } catch {
            continue;
          }
          for (const line of text.split("\n")) {
            if (line.length > 400 || line.trimEnd().endsWith(";")) continue;
            const equals = line.indexOf("=");
            if (equals !== -1 && equals < line.indexOf("(")) continue; // an assignment, not a declaration
            const match = DEFINITION.exec(line.replace(/<[^<>]*>/g, "").replace(/<[^<>]*>/g, "").replace(/<[^<>]*>/g, ""));
            const name = match?.[1];
            if (!name || KEYWORD.has(name)) continue;
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

  /** The declarations (with a body) called `name` in `file`. */
  private declarationsIn(file: string, name: string): SyntaxNode[] {
    const parsed = this.parse(file);
    if (!parsed) return [];
    const out: SyntaxNode[] = [];
    const stack: SyntaxNode[] = [parsed.tree.rootNode];
    while (stack.length > 0) {
      const node = stack.pop() as SyntaxNode;
      if (node.type === "method_declaration" && node.childForFieldName("name")?.text === name && node.childForFieldName("body")) out.push(node);
      else if (node.type === "program" || node.type === "class_declaration" || node.type === "class_body" || node.type === "enum_declaration" || node.type === "enum_body" || node.type === "interface_declaration" || node.type === "record_declaration") {
        for (const child of node.namedChildren) stack.push(child);
      }
    }
    return out;
  }

  parameterNames(fn: SyntaxNode): string[] {
    const names: string[] = [];
    for (const declaration of fn.childForFieldName("parameters")?.namedChildren ?? []) {
      if (declaration.type !== "formal_parameter" && declaration.type !== "spread_parameter") continue;
      names.push(declaration.childForFieldName("name")?.text ?? declaration.namedChildren.find((c) => c.type === "variable_declarator")?.childForFieldName("name")?.text ?? "_");
    }
    return names;
  }

  /** The method a call means, when that is certain: declared in this file, else the only one of its name (and argument count) in the project. */
  resolve(call: SyntaxNode, fromFile: string): MethodRef | undefined {
    const info = callInfo(call);
    if (!info || info.isNew || !info.name || COMMON.has(info.name.toLowerCase())) return undefined;
    const files = this.index().get(info.name);
    if (!files || files.length === 0) return undefined;
    const from = path.resolve(fromFile);
    const arity = info.args.length;
    const pick = (file: string): SyntaxNode | undefined => {
      const found = this.declarationsIn(file, info.name).filter((d) => d.childForFieldName("parameters")?.namedChildren.filter((c) => c.type === "formal_parameter" || c.type === "spread_parameter").length === arity);
      return found.length === 1 ? found[0] : undefined;
    };
    const unqualified = !info.receiverNode || info.receiverNode.type === "this";
    // the same file first (an unqualified call, `this.helper(x)`), then the only file in the project that declares the name
    if (files.some((f) => path.resolve(f) === from) && unqualified) {
      const own = pick(from);
      if (own) return { file: from, fn: own, name: info.name };
    }
    if (files.length !== 1) return undefined;
    const declaration = pick(files[0] as string);
    return declaration ? { file: files[0] as string, fn: declaration, name: info.name } : undefined;
  }

  private readonly returnSummaries = new Map<string, readonly number[]>();

  /** The positions of the arguments of `call` whose value the method hands back (`return` of a tainted parameter), when the method is known. */
  returnParams(call: SyntaxNode, fromFile: string): readonly number[] | undefined {
    const ref = this.resolveForReturn(call, fromFile);
    if (!ref) return undefined;
    const key = `${ref.file}:${ref.fn.startIndex}`;
    const known = this.returnSummaries.get(key);
    if (known) return known;
    if (this.inProgress.has(`r:${key}`)) return undefined;
    this.inProgress.add(`r:${key}`);
    const parsed = this.parse(ref.file);
    const out: number[] = [];
    if (parsed) {
      this.parameterNames(ref.fn).forEach((name, index) => {
        if (name === "_") return;
        let hit = false;
        trackTaint(ref.fn, NO_ROOTS, new Set([name]), parsed.sourceCode, {
          onReturn: (statement, tainted) => {
            const value = statement.namedChild(0);
            if (value && carriedBy(value, tainted, NO_ROOTS) !== undefined) hit = true;
          },
        });
        if (hit) out.push(index);
      });
    }
    this.inProgress.delete(`r:${key}`);
    this.returnSummaries.set(key, out);
    return out;
  }

  /** Like resolve(), and also a method of a class declared in this file called through `new Helper().method(...)`. */
  private resolveForReturn(call: SyntaxNode, fromFile: string): MethodRef | undefined {
    const info = callInfo(call);
    if (!info || info.isNew || !info.name || COMMON.has(info.name.toLowerCase())) return undefined;
    const viaNew = info.receiverNode?.type === "object_creation_expression";
    if (viaNew) {
      const from = path.resolve(fromFile);
      const own = this.declarationsIn(from, info.name).filter((d) => d.childForFieldName("parameters")?.namedChildren.filter((c) => c.type === "formal_parameter" || c.type === "spread_parameter").length === info.args.length);
      return own.length === 1 && own[0] ? { file: from, fn: own[0], name: info.name } : undefined;
    }
    return this.resolve(call, fromFile);
  }

  /** For each parameter of `ref` (by position) that reaches a dangerous call: the first place it does. */
  summary(ref: MethodRef, depth = 0): Map<number, Hit> {
    const key = `${ref.file}:${ref.fn.startIndex}`;
    const known = this.summaries.get(key);
    if (known) return known;
    const result = new Map<number, Hit>();
    if (depth > MAX_DEPTH || this.inProgress.has(key)) return result;
    this.inProgress.add(key);
    const parsed = this.parse(ref.file);
    const names = this.parameterNames(ref.fn);
    // a method that reads the request itself is a handler, not a helper: its own findings are reported there
    if (parsed && !hasRoots(rootsOf(ref.fn, parsed.sourceCode))) {
      const text = parsed.sourceCode;
      names.forEach((name, index) => {
        if (name === "_" || result.has(index)) return;
        checkBudgetNow();
        trackTaint(ref.fn, NO_ROOTS, new Set([name]), text, {
          onCall: (call, tainted) => {
            if (result.has(index)) return;
            for (const spec of sinksOf(call, NO_ROOTS, ref.fn.text)) {
              const via = spec.args.map((arg) => carriedBy(arg, tainted, NO_ROOTS)).find((v) => v !== undefined);
              if (via === undefined) continue;
              result.set(index, { spec, file: ref.file, line: call.startPosition.row + 1, chain: [] });
              return;
            }
            // one more helper deeper
            const next = this.resolve(call, ref.file);
            if (!next || (next.fn.id === ref.fn.id && next.file === ref.file)) return;
            for (const [position, hit] of this.summary(next, depth + 1)) {
              const arg = argumentsOf(call)[position];
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
