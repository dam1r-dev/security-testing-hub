import * as fs from "fs";
import * as path from "path";
import { checkBudgetNow } from "../budget";
import { ParsedFile, parseFile } from "../parsers/ast-parser";
import { SyntaxNode, findNodes } from "../parsers/utils";
import { ProjectContext } from "../taint/project";
import { calleeText, callArguments, carriedBy, trackTaint } from "./engine";
import { parametersOf } from "./origins";
import { SinkSpec, sinksOf } from "./sinks";

/**
 * What the rest of the project does with a value handed to it. A view calls `get_user(name)` from `app/db.py`; the SQL is built there.
 * The project index resolves the call (imports, `from .db import x`, `import db`, methods of imported classes), works out which
 * parameters of the callee reach a dangerous call (following calls to other helpers up to three deep), and reports the finding at the
 * call in the view, naming the place the value ends up. Reads other files through `fs`, so the same code runs in the browser build.
 */

const MAX_FILE_BYTES = 1024 * 1024;
const MAX_DEPTH = 3;

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

type Target = { kind: "module"; file: string } | { kind: "symbol"; file: string; name: string };

const COMMON_METHOD = new Set(["get", "set", "add", "remove", "delete", "update", "save", "create", "read", "write", "close", "open", "run", "start", "stop", "items", "keys", "values", "append", "extend", "pop", "join", "split", "strip", "format", "encode", "decode", "send", "post", "put", "patch", "head", "filter", "all", "first", "last", "count", "exists", "execute"]);

export class PythonProject {
  private static readonly instances = new WeakMap<ProjectContext, PythonProject>();
  private readonly parsed = new Map<string, ParsedFile | null>();
  private readonly importMaps = new Map<string, Map<string, Target>>();
  private readonly functions = new Map<string, Map<string, SyntaxNode[]>>();
  private readonly classes = new Map<string, Map<string, SyntaxNode>>();
  private readonly summaries = new Map<string, Map<number, Hit>>();
  private readonly inProgress = new Set<string>();
  private readonly existsCache = new Map<string, boolean>();

  private constructor(readonly context: ProjectContext) {}

  static of(context: ProjectContext): PythonProject {
    let project = PythonProject.instances.get(context);
    if (!project) {
      project = new PythonProject(context);
      PythonProject.instances.set(context, project);
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

  private isFile(candidate: string): boolean {
    let known = this.existsCache.get(candidate);
    if (known === undefined) {
      try {
        known = fs.statSync(candidate).isFile();
      } catch {
        known = false;
      }
      this.existsCache.set(candidate, known);
    }
    return known;
  }

  /** `app.db` seen from `fromFile` -> the file that holds it (`app/db.py` or `app/db/__init__.py`). `level` is the number of leading dots. */
  moduleFile(parts: string[], fromFile: string, level: number): string | undefined {
    const tails = parts.length > 0 ? [`${parts.join("/")}.py`, `${parts.join("/")}/__init__.py`] : ["__init__.py"];
    const roots: string[] = [];
    if (level > 0) {
      let base = path.dirname(path.resolve(fromFile));
      for (let i = 1; i < level; i++) base = path.dirname(base);
      roots.push(base);
    } else {
      // like sys.path: the project root, the folders above the importing file, and the usual `src/`
      let dir = path.dirname(path.resolve(fromFile));
      for (let depth = 0; depth < 8; depth++) {
        roots.push(dir);
        if (dir === this.context.root) break;
        const parent = path.dirname(dir);
        if (parent === dir) break;
        dir = parent;
      }
      roots.push(this.context.root, path.join(this.context.root, "src"));
    }
    for (const root of roots) {
      for (const tail of tails) {
        const candidate = path.join(root, tail);
        if (this.isFile(candidate)) return candidate;
      }
    }
    return undefined;
  }

  importsOf(file: string): Map<string, Target> {
    const key = path.resolve(file);
    let map = this.importMaps.get(key);
    if (map) return map;
    map = new Map();
    this.importMaps.set(key, map);
    const parsed = this.parse(key);
    if (!parsed) return map;
    for (const statement of parsed.tree.rootNode.namedChildren) {
      if (statement.type === "import_statement") {
        for (const item of statement.namedChildren) {
          const dotted = item.type === "aliased_import" ? item.namedChild(0) : item;
          const alias = item.type === "aliased_import" ? item.namedChild(1)?.text : undefined;
          if (dotted?.type !== "dotted_name") continue;
          const parts = dotted.text.split(".");
          const target = this.moduleFile(parts, key, 0);
          if (target) map.set(alias ?? parts[parts.length - 1] ?? "", { kind: "module", file: target });
        }
      } else if (statement.type === "import_from_statement") {
        const moduleNode = statement.childForFieldName("module_name");
        let level = 0;
        let parts: string[] = [];
        if (moduleNode?.type === "relative_import") {
          level = moduleNode.namedChildren.find((c) => c.type === "import_prefix")?.text.length ?? 1;
          parts = moduleNode.namedChildren.find((c) => c.type === "dotted_name")?.text.split(".") ?? [];
        } else if (moduleNode) {
          parts = moduleNode.text.split(".");
        }
        const moduleFile = this.moduleFile(parts, key, level);
        for (const item of statement.namedChildren) {
          if (item.id === moduleNode?.id) continue;
          const dotted = item.type === "aliased_import" ? item.namedChild(0) : item;
          const alias = item.type === "aliased_import" ? item.namedChild(1)?.text : undefined;
          if (dotted?.type !== "dotted_name") continue;
          const name = dotted.text;
          const local = alias ?? name;
          // `from app import db`: the name may be a module of its own
          const asModule = this.moduleFile([...parts, name], key, level);
          if (asModule) map.set(local, { kind: "module", file: asModule });
          else if (moduleFile) map.set(local, { kind: "symbol", file: moduleFile, name });
        }
      }
    }
    return map;
  }

  /** Functions and methods of `file` by name (module level and inside classes). */
  functionsIn(file: string): Map<string, SyntaxNode[]> {
    const key = path.resolve(file);
    let map = this.functions.get(key);
    if (map) return map;
    map = new Map();
    this.functions.set(key, map);
    const parsed = this.parse(key);
    if (!parsed) return map;
    for (const fn of findNodes(parsed.tree.rootNode, (n) => n.type === "function_definition")) {
      const name = fn.childForFieldName("name")?.text;
      if (name) map.set(name, [...(map.get(name) ?? []), fn]);
    }
    return map;
  }

  classesIn(file: string): Map<string, SyntaxNode> {
    const key = path.resolve(file);
    let map = this.classes.get(key);
    if (map) return map;
    map = new Map();
    this.classes.set(key, map);
    const parsed = this.parse(key);
    if (!parsed) return map;
    for (const klass of parsed.tree.rootNode.namedChildren) {
      const node = klass.type === "decorated_definition" ? klass.childForFieldName("definition") : klass;
      if (node?.type === "class_definition") {
        const name = node.childForFieldName("name")?.text;
        if (name) map.set(name, node);
      }
    }
    return map;
  }

  private unique(candidates: SyntaxNode[] | undefined): SyntaxNode | undefined {
    return candidates && candidates.length === 1 ? candidates[0] : undefined;
  }

  /** The function a call goes to, if it is one of the project's. */
  resolve(call: SyntaxNode, file: string, inside: SyntaxNode | undefined, tainted: ReadonlySet<string>): FunctionRef | undefined {
    const key = path.resolve(file);
    const callee = call.childForFieldName("function");
    if (!callee) return undefined;
    // Resolving costs file reads and parses: only a call that is handed the caller's value can matter.
    const { positional, keywords } = callArguments(call);
    if (![...positional, ...keywords.values()].some((a) => carriedBy(a, tainted) !== undefined)) return undefined;
    const imports = this.importsOf(key);

    if (callee.type === "identifier") {
      const local = this.unique(this.functionsIn(key).get(callee.text));
      if (local && local.id !== inside?.id) return { file: key, fn: local, name: callee.text };
      const target = imports.get(callee.text);
      if (target?.kind === "symbol") {
        const fn = this.unique(this.functionsIn(target.file).get(target.name));
        if (fn) return { file: target.file, fn, name: target.name };
        // `from services import UserService` then `UserService(...)`: a constructor, not followed
      }
      return undefined;
    }

    if (callee.type === "attribute") {
      const object = callee.childForFieldName("object");
      const method = callee.childForFieldName("attribute")?.text ?? "";
      if (!object || !method) return undefined;
      if (object.type === "identifier" && /^(?:self|cls)$/.test(object.text)) {
        const fn = this.unique(this.functionsIn(key).get(method));
        return fn && fn.id !== inside?.id ? { file: key, fn, name: method } : undefined;
      }
      if (object.type === "identifier") {
        const target = imports.get(object.text);
        if (target?.kind === "module") {
          const fn = this.unique(this.functionsIn(target.file).get(method));
          if (fn) return { file: target.file, fn, name: `${object.text}.${method}` };
        }
        if (target?.kind === "symbol") {
          // `UserService.find(x)` on an imported class
          const klass = this.classesIn(target.file).get(target.name);
          const fn = klass ? this.unique(findNodes(klass, (n) => n.type === "function_definition" && n.childForFieldName("name")?.text === method)) : undefined;
          if (fn) return { file: target.file, fn, name: `${target.name}.${method}` };
        }
      }
      // `service.find(x)` / `UserService().find(x)`: the method name, among the classes this file imports
      if (!COMMON_METHOD.has(method)) {
        const matches: FunctionRef[] = [];
        for (const target of imports.values()) {
          if (target.kind !== "symbol") continue;
          const klass = this.classesIn(target.file).get(target.name);
          if (!klass) continue;
          for (const fn of findNodes(klass, (n) => n.type === "function_definition" && n.childForFieldName("name")?.text === method)) {
            matches.push({ file: target.file, fn, name: `${target.name}.${method}` });
          }
        }
        if (matches.length === 1) return matches[0];
      }
    }
    return undefined;
  }

  /** For each parameter of `ref` (counting from the first after `self` / `cls`), the dangerous call its value ends up in. */
  summary(ref: FunctionRef, depth = 0): Map<number, Hit> {
    const key = `${ref.file}:${ref.fn.startIndex}`;
    const known = this.summaries.get(key);
    if (known) return known;
    if (this.inProgress.has(key) || depth > MAX_DEPTH) return new Map();
    this.inProgress.add(key);
    const hits = new Map<number, Hit>();
    try {
      checkBudgetNow();
      const parsed = this.parse(ref.file);
      const text = parsed?.sourceCode ?? "";
      const parameters = parametersOf(ref.fn).filter((p) => p.name !== "self" && p.name !== "cls");
      parameters.forEach((parameter, index) => {
        if (parameter.variadic) return;
        trackTaint(ref.fn, new Set([parameter.name]), {
          onCall: (call, tainted) => {
            if (hits.has(index)) return;
            for (const spec of sinksOf(call, text)) {
              if (spec.args.some((a) => carriedBy(a, tainted) !== undefined)) {
                hits.set(index, { spec, file: ref.file, line: call.startPosition.row + 1, chain: [] });
                return;
              }
            }
            const next = this.resolve(call, ref.file, ref.fn, tainted);
            if (!next) return;
            for (const [nextIndex, hit] of this.summary(next, depth + 1)) {
              const argument = argumentFor(call, next.fn, nextIndex);
              if (argument && carriedBy(argument, tainted) !== undefined) {
                hits.set(index, { ...hit, chain: [next.name, ...hit.chain] });
                return;
              }
            }
          },
        });
      });
    } finally {
      this.inProgress.delete(key);
    }
    this.summaries.set(key, hits);
    return hits;
  }
}

/** The argument of `call` that arrives as parameter number `index` of `fn` (positional, or by keyword name). */
export function argumentFor(call: SyntaxNode, fn: SyntaxNode, index: number): SyntaxNode | undefined {
  const parameters = parametersOf(fn).filter((p) => p.name !== "self" && p.name !== "cls");
  const { positional, keywords } = callArguments(call);
  const direct = positional[index];
  if (direct && direct.type !== "list_splat" && direct.type !== "dictionary_splat") return direct;
  const name = parameters[index]?.name;
  return name ? keywords.get(name) : undefined;
}

export function describeCall(call: SyntaxNode): string {
  return calleeText(call);
}
