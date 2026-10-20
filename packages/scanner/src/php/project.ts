import * as fs from "fs";
import * as path from "path";
import { checkBudgetNow } from "../budget";
import { ParsedFile, parseFile } from "../parsers/ast-parser";
import { SyntaxNode, findNodes } from "../parsers/utils";
import { ProjectContext } from "../taint/project";
import { argumentsOf, calleeName, carriedBy, trackTaint } from "./engine";
import { Sink, sinksOf } from "./sinks";

/**
 * What the rest of the project does with a value handed to it. A controller calls `find_user($name)` or `UserService::find($name)` or
 * `$this->users->find($name)`; the SQL is built in another file. PHP functions live in one global namespace and classes are found by
 * name, so the project is indexed once (every `.php` file under the scanned folder) and a call is matched by name:
 *  - a plain function call -> the one project function of that name;
 *  - `Class::method()` -> that method of the class of that name;
 *  - `$this->method()` -> the method of the same class; `$object->method()` -> the method of that name in the classes this file mentions
 *    (`use`, `new`, a type hint), when exactly one matches.
 * Which parameters of the callee reach a dangerous call is worked out as for Python (python/project.ts), up to three calls deep.
 */

const MAX_FILES = 4000;
const MAX_FILE_BYTES = 1024 * 1024;
const MAX_DEPTH = 3;
const SKIP_DIRS = new Set(["vendor", "node_modules", ".git", "storage", "cache", "tests", "test", "__tests__", "public"]);
const COMMON_METHOD = new Set(["get", "set", "add", "all", "find", "first", "create", "update", "delete", "save", "count", "exists", "map", "filter", "each", "pluck", "where", "with", "query", "execute", "run", "handle", "boot", "register", "toArray", "toString", "__construct"]);

export interface Hit {
  sink: Sink;
  file: string;
  line: number;
  chain: string[];
}

export interface FunctionRef {
  file: string;
  fn: SyntaxNode;
  name: string;
}

export function parameterNames(fn: SyntaxNode): Array<{ name: string; type: string }> {
  const out: Array<{ name: string; type: string }> = [];
  for (const parameter of fn.childForFieldName("parameters")?.namedChildren ?? []) {
    if (parameter.type !== "simple_parameter" && parameter.type !== "variadic_parameter" && parameter.type !== "property_promotion_parameter") continue;
    const name = parameter.childForFieldName("name");
    if (name) out.push({ name: name.text, type: parameter.childForFieldName("type")?.text ?? "" });
  }
  return out;
}

/** The argument of `call` that arrives as parameter number `index` of `fn`. */
export function argumentFor(call: SyntaxNode, _fn: SyntaxNode, index: number): SyntaxNode | undefined {
  return argumentsOf(call)[index];
}

function shortName(name: string): string {
  return name.replace(/^\\/, "").split("\\").pop() ?? name;
}

export class PhpProject {
  private static readonly instances = new WeakMap<ProjectContext, PhpProject>();
  private readonly parsed = new Map<string, ParsedFile | null>();
  private readonly summaries = new Map<string, Map<number, Hit>>();
  private readonly inProgress = new Set<string>();
  private readonly mentioned = new Map<string, Set<string>>();
  private indexed = false;
  // Names found in the text of every file, without parsing it: a function name -> the files that mention `function name(`.
  private readonly functionFiles = new Map<string, Set<string>>();
  private readonly classFiles = new Map<string, Set<string>>();
  private readonly globalCache = new Map<string, FunctionRef[]>();
  private readonly classCache = new Map<string, Array<{ file: string; node: SyntaxNode }>>();

  private constructor(readonly context: ProjectContext) {}

  static of(context: ProjectContext): PhpProject {
    let project = PhpProject.instances.get(context);
    if (!project) {
      project = new PhpProject(context);
      PhpProject.instances.set(context, project);
    }
    return project;
  }

  parse(file: string, known?: ParsedFile): ParsedFile | undefined {
    const key = path.resolve(file);
    if (known) this.parsed.set(key, known);
    const cached = this.parsed.get(key);
    if (cached !== undefined) return cached ?? undefined;
    let result: ParsedFile | undefined;
    try {
      if (fs.statSync(key).size <= MAX_FILE_BYTES) result = parseFile(key, fs.readFileSync(key, "utf8"));
    } catch {
      result = undefined;
    }
    this.parsed.set(key, result ?? null);
    if (result) this.context.fileInfo(key, result);
    return result;
  }

  /**
   * Which files define which functions and classes, found by reading the text of every `.php` file under the scanned folder once (a
   * pattern match, no parse). A file is only parsed when a call actually leads to it.
   */
  private ensureIndex(current?: { file: string; parsed: ParsedFile }): void {
    if (this.indexed) return;
    this.indexed = true;
    if (current) this.parse(current.file, current.parsed);
    const files: string[] = [];
    const stack = [this.context.root];
    while (stack.length > 0 && files.length < MAX_FILES) {
      const dir = stack.pop() as string;
      let entries: fs.Dirent[];
      try {
        entries = fs.readdirSync(dir, { withFileTypes: true }) as fs.Dirent[];
      } catch {
        continue;
      }
      for (const entry of entries) {
        if (entry.name.startsWith(".")) continue;
        const full = path.join(dir, entry.name);
        if (entry.isDirectory()) {
          if (!SKIP_DIRS.has(entry.name)) stack.push(full);
        } else if (entry.isFile() && entry.name.endsWith(".php")) {
          files.push(full);
        }
      }
    }
    const add = (map: Map<string, Set<string>>, name: string, file: string): void => {
      const set = map.get(name) ?? new Set<string>();
      set.add(file);
      map.set(name, set);
    };
    for (const file of files) {
      checkBudgetNow();
      let text: string;
      try {
        if (fs.statSync(file).size > MAX_FILE_BYTES) continue;
        text = fs.readFileSync(file, "utf8");
      } catch {
        continue;
      }
      for (const m of text.matchAll(/\bfunction\s+&?\s*([A-Za-z_]\w*)\s*\(/g)) add(this.functionFiles, (m[1] as string).toLowerCase(), file);
      for (const m of text.matchAll(/\b(?:class|trait)\s+([A-Za-z_]\w*)/g)) add(this.classFiles, m[1] as string, file);
    }
  }

  /** The project functions of this name (not methods): the files that mention it are parsed and checked. */
  private globalFunctionsNamed(name: string): FunctionRef[] {
    const key = name.toLowerCase();
    const cached = this.globalCache.get(key);
    if (cached) return cached;
    const out: FunctionRef[] = [];
    for (const file of this.functionFiles.get(key) ?? []) {
      const parsed = this.parse(file);
      if (!parsed) continue;
      for (const fn of findNodes(parsed.tree.rootNode, (n) => n.type === "function_definition" && n.childForFieldName("name")?.text.toLowerCase() === key)) out.push({ file, fn, name });
    }
    this.globalCache.set(key, out);
    return out;
  }

  private classesNamed(name: string): Array<{ file: string; node: SyntaxNode }> {
    const cached = this.classCache.get(name);
    if (cached) return cached;
    const out: Array<{ file: string; node: SyntaxNode }> = [];
    for (const file of this.classFiles.get(name) ?? []) {
      const parsed = this.parse(file);
      if (!parsed) continue;
      for (const node of findNodes(parsed.tree.rootNode, (n) => (n.type === "class_declaration" || n.type === "trait_declaration") && n.childForFieldName("name")?.text === name)) out.push({ file, node });
    }
    this.classCache.set(name, out);
    return out;
  }

  private readonly methodIndex = new Map<string, Map<string, FunctionRef[]>>();

  private methodsOf(className: string, method: string): FunctionRef[] {
    let byMethod = this.methodIndex.get(className);
    if (!byMethod) {
      byMethod = new Map();
      this.methodIndex.set(className, byMethod);
      for (const { file, node } of this.classesNamed(className)) {
        for (const fn of findNodes(node, (n) => n.type === "method_declaration")) {
          const name = fn.childForFieldName("name")?.text;
          if (name) byMethod.set(name.toLowerCase(), [...(byMethod.get(name.toLowerCase()) ?? []), { file, fn, name: `${className}::${name}` }]);
        }
      }
    }
    return byMethod.get(method.toLowerCase()) ?? [];
  }

  /** The class names a file mentions: `use App\Services\UserService;`, `new UserService`, `UserService $service`. */
  private classesMentionedIn(file: string, text: string): Set<string> {
    let names = this.mentioned.get(file);
    if (names) return names;
    names = new Set();
    for (const m of text.matchAll(/\buse\s+([\w\\]+?)(?:\s+as\s+(\w+))?\s*[;,]/g)) names.add(shortName(m[1] as string));
    for (const m of text.matchAll(/\bnew\s+\\?([A-Za-z_][\w\\]*)/g)) names.add(shortName(m[1] as string));
    for (const m of text.matchAll(/\b([A-Z]\w+)\s+\$\w+/g)) names.add(m[1] as string);
    this.mentioned.set(file, names);
    return names;
  }

  /** The function a call goes to, if it is one of the project's. */
  resolve(call: SyntaxNode, file: string, parsed: ParsedFile, inside: SyntaxNode | undefined, tainted: { has(name: string): boolean }): FunctionRef | undefined {
    const key = path.resolve(file);
    const kind = call.type;
    if (kind !== "function_call_expression" && kind !== "member_call_expression" && kind !== "scoped_call_expression") return undefined;
    // The index and the resolution cost something: only a call that is handed the caller's value can matter.
    if (!argumentsOf(call).some((a) => carriedBy(a, tainted) !== undefined)) return undefined;
    this.ensureIndex({ file: key, parsed });

    if (kind === "function_call_expression") {
      const name = calleeName(call);
      const found = this.globalFunctionsNamed(name);
      return found && found.length === 1 && found[0] && found[0].fn.id !== inside?.id ? found[0] : undefined;
    }

    const method = call.childForFieldName("name")?.text ?? "";
    if (!method) return undefined;

    if (kind === "scoped_call_expression") {
      const scope = shortName(call.childForFieldName("scope")?.text ?? "");
      if (/^(?:self|static|parent)$/.test(scope)) return this.sameClassMethod(call, method, inside, key);
      const found = this.methodsOf(scope, method);
      return found.length === 1 ? found[0] : undefined;
    }

    const object = call.childForFieldName("object");
    if (object?.text === "$this") return this.sameClassMethod(call, method, inside, key);
    if (COMMON_METHOD.has(method)) return undefined;
    const matches: FunctionRef[] = [];
    for (const className of this.classesMentionedIn(key, parsed.sourceCode)) matches.push(...this.methodsOf(className, method));
    return matches.length === 1 && matches[0] && matches[0].fn.id !== inside?.id ? matches[0] : undefined;
  }

  private sameClassMethod(call: SyntaxNode, method: string, inside: SyntaxNode | undefined, file: string): FunctionRef | undefined {
    let klass: SyntaxNode | null = call.parent;
    while (klass && klass.type !== "class_declaration" && klass.type !== "trait_declaration") klass = klass.parent;
    if (!klass) return undefined;
    const matches = findNodes(klass, (n) => n.type === "method_declaration" && n.childForFieldName("name")?.text === method);
    const fn = matches.length === 1 ? matches[0] : undefined;
    return fn && fn.id !== inside?.id ? { file, fn, name: `$this->${method}` } : undefined;
  }

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
      if (!parsed) return hits;
      const text = parsed.sourceCode;
      parameterNames(ref.fn).forEach((parameter, index) => {
        trackTaint(ref.fn, [parameter.name], (node, tainted) => {
          if (hits.has(index)) return;
          for (const sink of sinksOf(node, text)) {
            if (sink.args.some((a) => carriedBy(a, tainted) !== undefined)) {
              hits.set(index, { sink, file: ref.file, line: node.startPosition.row + 1, chain: [] });
              return;
            }
          }
          const next = this.resolve(node, ref.file, parsed, ref.fn, tainted);
          if (!next) return;
          for (const [nextIndex, hit] of this.summary(next, depth + 1)) {
            const argument = argumentFor(node, next.fn, nextIndex);
            if (argument && carriedBy(argument, tainted) !== undefined) {
              hits.set(index, { ...hit, chain: [next.name, ...hit.chain] });
              return;
            }
          }
        });
      });
    } finally {
      this.inProgress.delete(key);
    }
    this.summaries.set(key, hits);
    return hits;
  }
}
