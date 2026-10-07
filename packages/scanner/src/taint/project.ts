import * as fs from "fs";
import * as path from "path";
import { ParsedFile, languageForExtension, parseFile } from "../parsers/ast-parser";
import { SyntaxNode, findNodes } from "../parsers/utils";
import { assignmentLike, boundNames } from "./simple-taint";

/**
 * A lightweight, lazy model of "what does this name refer to?" across files:
 * enough module-system knowledge (ESM `import`, CommonJS `require` / `exports`,
 * object literals, classes, constructor functions, `this`) to follow a call like
 * `userService.findByName(x)` or `dao.getByUserId(id)` into the function that
 * actually runs the query — which usually lives in another file.
 *
 * Nothing is indexed up front: a file is parsed and modelled only when a call
 * site that carries tainted data needs it, and parsed files sit in a bounded
 * cache so a big project can't exhaust memory.
 *
 * This is a name-based resolver, not a type checker. Whatever it cannot resolve
 * (dynamic `require`, factories returning objects, DI containers, ...) it
 * leaves alone — a missed flow is a false negative, never an invented finding.
 */

export interface FunctionInfo {
  info: FileInfo;
  file: string;
  node: SyntaxNode;
  name: string;
  /** Names bound by each positional parameter (destructuring binds several). */
  params: string[][];
  body: SyntaxNode | null;
}

interface Scope {
  info: FileInfo;
  node: SyntaxNode;
}

export type Entity =
  | { kind: "fn"; fn: FunctionInfo }
  | { kind: "obj"; members: Map<string, Entity> }
  | { kind: "class"; node: SyntaxNode; info: FileInfo }
  | { kind: "ref"; name: string; at: Scope }
  | { kind: "member"; object: Entity; name: string }
  | { kind: "import"; spec: string; name: string; info: FileInfo }
  | { kind: "instance"; of: Entity };

interface ModuleExports {
  named: Map<string, Entity>;
  defaultExport?: Entity;
  /** `module.exports = X` */
  commonjs?: Entity;
  /** `export * from "./x"` */
  stars: string[];
}

const MAX_CACHED_FILES = 400;
const MAX_RESOLVE_DEPTH = 12;
const EXTENSIONS = [".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"];

function stringValue(node: SyntaxNode): string {
  return node.text.replace(/^["'`]|["'`]$/g, "");
}

function unwrap(node: SyntaxNode): SyntaxNode {
  let current = node;
  for (;;) {
    if (
      current.type === "parenthesized_expression" ||
      current.type === "await_expression" ||
      current.type === "as_expression" ||
      current.type === "satisfies_expression" ||
      current.type === "non_null_expression" ||
      current.type === "type_assertion"
    ) {
      const inner = current.namedChild(0);
      if (!inner) return current;
      current = inner;
    } else {
      return current;
    }
  }
}

function isFunctionLike(node: SyntaxNode): boolean {
  return (
    node.type === "function_declaration" ||
    node.type === "function_expression" ||
    node.type === "function" ||
    node.type === "arrow_function" ||
    node.type === "method_definition"
  );
}

function parameterNames(fnNode: SyntaxNode): string[][] {
  const single = fnNode.childForFieldName("parameter"); // x => ...
  if (single) return [boundNames(single)];
  const params = fnNode.childForFieldName("parameters");
  if (!params) return [];
  return params.namedChildren
    .filter((p) => p.type !== "comment")
    .map((p) => {
      if (p.type === "required_parameter" || p.type === "optional_parameter") {
        const pattern = p.childForFieldName("pattern");
        return pattern ? boundNames(pattern) : [];
      }
      return boundNames(p);
    });
}

/** `require("./x")` -> "./x" */
function requireSpecifier(call: SyntaxNode): string | undefined {
  if (call.type !== "call_expression") return undefined;
  const callee = call.childForFieldName("function");
  if (callee?.type !== "identifier" || callee.text !== "require") return undefined;
  const first = call.childForFieldName("arguments")?.namedChild(0);
  return first?.type === "string" ? stringValue(first) : undefined;
}

/** tsconfig.json allows comments; strip them without touching string contents such as "@/*". */
function stripJsonComments(text: string): string {
  let out = "";
  let inString = false;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i] as string;
    const next = text[i + 1];
    if (inString) {
      out += ch;
      if (ch === "\\") out += text[++i] ?? "";
      else if (ch === '"') inString = false;
    } else if (ch === '"') {
      inString = true;
      out += ch;
    } else if (ch === "/" && next === "/") {
      while (i < text.length && text[i] !== "\n") i++;
      out += "\n";
    } else if (ch === "/" && next === "*") {
      i += 2;
      while (i < text.length && !(text[i] === "*" && text[i + 1] === "/")) i++;
      i++;
    } else {
      out += ch;
    }
  }
  return out;
}

function rangeKey(node: SyntaxNode): string {
  return `${node.startIndex}:${node.endIndex}:${node.type}`;
}

function isStatic(member: SyntaxNode): boolean {
  return member.children.some((c) => c.type === "static");
}

/** Statements directly inside `fn` — never descending into nested functions, so `this` stays the same. */
function collectThisAssignments(root: SyntaxNode, out: SyntaxNode[]): void {
  for (const child of root.namedChildren) {
    if (isFunctionLike(child) || child.type === "class_declaration" || child.type === "class") continue;
    if (child.type === "assignment_expression") {
      const left = child.childForFieldName("left");
      if (left?.type === "member_expression" && left.childForFieldName("object")?.type === "this") out.push(child);
    }
    collectThisAssignments(child, out);
  }
}

export class FileInfo {
  private readonly scopeCache = new Map<string, Map<string, Entity>>();
  private readonly functionCache = new Map<string, FunctionInfo>();
  private readonly memberCache = new Map<string, Map<string, Entity>>();
  private exportsCache?: ModuleExports;
  private readonly nodeListCache = new Map<string, SyntaxNode[]>();
  private readonly sourceCache = new Map<(n: SyntaxNode) => boolean, Map<string, SyntaxNode[]>>();

  constructor(
    readonly project: ProjectContext,
    readonly file: string,
    readonly parsed: ParsedFile,
  ) {}

  get root(): SyntaxNode {
    return this.parsed.tree.rootNode;
  }

  // ---- shared per-scope walks -------------------------------------------
  // Walking a tree through the native binding is the dominant cost of a scan, and a
  // dozen rules ask the same questions of the same function: do it once.

  /** Source nodes in `scope` for `isSource` (rules sharing one predicate share the walk). */
  sourcesIn(scope: SyntaxNode, isSource: (n: SyntaxNode) => boolean): SyntaxNode[] {
    let perScope = this.sourceCache.get(isSource);
    if (!perScope) {
      perScope = new Map();
      this.sourceCache.set(isSource, perScope);
    }
    const key = rangeKey(scope);
    let found = perScope.get(key);
    if (!found) {
      found = findNodes(scope, isSource);
      perScope.set(key, found);
    }
    return found;
  }

  /** Every call / `new` expression in `scope`. */
  callsIn(scope: SyntaxNode): SyntaxNode[] {
    return this.memoNodes(`calls:${rangeKey(scope)}`, () =>
      findNodes(scope, (n) => n.type === "call_expression" || n.type === "new_expression"),
    );
  }

  /** Every declaration / assignment in `scope`. */
  assignmentsIn(scope: SyntaxNode): SyntaxNode[] {
    return this.memoNodes(`assign:${rangeKey(scope)}`, () => assignmentLike(scope));
  }

  private memoNodes(key: string, compute: () => SyntaxNode[]): SyntaxNode[] {
    let found = this.nodeListCache.get(key);
    if (!found) {
      found = compute();
      this.nodeListCache.set(key, found);
    }
    return found;
  }

  functionInfo(node: SyntaxNode, name?: string): FunctionInfo {
    const key = rangeKey(node);
    const cached = this.functionCache.get(key);
    if (cached) return cached;
    const own = node.childForFieldName("name")?.text;
    const info: FunctionInfo = {
      info: this,
      file: this.file,
      node,
      name: own ?? name ?? "anonymous",
      params: parameterNames(node),
      body: node.childForFieldName("body"),
    };
    this.functionCache.set(key, info);
    return info;
  }

  // ---- names -> entities --------------------------------------------------

  /** What does `name` mean at `from`? Walks outward through lexical scopes; a parameter of the same name shadows (-> unknown). */
  lookup(name: string, from: SyntaxNode): Entity | undefined {
    let current: SyntaxNode | null = from;
    while (current) {
      if (isFunctionLike(current) && parameterNames(current).some((names) => names.includes(name))) return undefined;
      if (current.type === "statement_block" || current.type === "program") {
        const entity = this.declarations(current).get(name);
        if (entity) return entity;
      }
      current = current.parent;
    }
    return undefined;
  }

  private declarations(scope: SyntaxNode): Map<string, Entity> {
    const key = rangeKey(scope);
    const cached = this.scopeCache.get(key);
    if (cached) return cached;
    const map = new Map<string, Entity>();
    this.scopeCache.set(key, map); // set first: lookups during construction must not recurse forever
    for (const statement of scope.namedChildren) this.collectDeclaration(statement, map);
    return map;
  }

  private collectDeclaration(statement: SyntaxNode, map: Map<string, Entity>): void {
    let node = statement;
    if (node.type === "export_statement") {
      const declaration = node.childForFieldName("declaration");
      if (!declaration) return;
      node = declaration;
    }
    switch (node.type) {
      case "function_declaration":
      case "class_declaration": {
        const name = node.childForFieldName("name")?.text;
        const entity = this.entityFromExpr(node);
        if (name && entity) map.set(name, entity);
        return;
      }
      case "lexical_declaration":
      case "variable_declaration":
        for (const declarator of node.namedChildren) {
          if (declarator.type !== "variable_declarator") continue;
          const nameNode = declarator.childForFieldName("name");
          const value = declarator.childForFieldName("value");
          if (!nameNode || !value) continue;
          if (nameNode.type === "identifier") {
            const entity = this.entityFromExpr(value, nameNode.text);
            if (entity) map.set(nameNode.text, entity);
          } else if (nameNode.type === "object_pattern") {
            // const { a, b: c } = require("./x")  /  const { query } = db
            const object = this.entityFromExpr(value);
            if (!object) continue;
            for (const binding of nameNode.namedChildren) {
              if (binding.type === "shorthand_property_identifier_pattern") {
                map.set(binding.text, { kind: "member", object, name: binding.text });
              } else if (binding.type === "pair_pattern") {
                const key = binding.childForFieldName("key")?.text;
                const alias = binding.childForFieldName("value");
                if (key && alias?.type === "identifier") map.set(alias.text, { kind: "member", object, name: key });
              }
            }
          }
        }
        return;
      case "import_statement":
        this.collectImports(node, map);
        return;
      default:
        return;
    }
  }

  private collectImports(node: SyntaxNode, map: Map<string, Entity>): void {
    const source = node.childForFieldName("source");
    const clause = node.namedChildren.find((c) => c.type === "import_clause");
    if (!source || !clause) return;
    const spec = stringValue(source);
    for (const child of clause.namedChildren) {
      if (child.type === "identifier") {
        map.set(child.text, { kind: "import", spec, name: "default", info: this });
      } else if (child.type === "namespace_import") {
        const id = child.namedChildren.find((c) => c.type === "identifier");
        if (id) map.set(id.text, { kind: "import", spec, name: "*", info: this });
      } else if (child.type === "named_imports") {
        for (const specifier of child.namedChildren) {
          if (specifier.type !== "import_specifier") continue;
          const name = specifier.childForFieldName("name")?.text;
          const alias = specifier.childForFieldName("alias")?.text;
          if (name) map.set(alias ?? name, { kind: "import", spec, name, info: this });
        }
      }
    }
  }

  entityFromExpr(raw: SyntaxNode, name?: string): Entity | undefined {
    const node = unwrap(raw);
    switch (node.type) {
      case "function_declaration":
      case "function_expression":
      case "function":
      case "arrow_function":
        return { kind: "fn", fn: this.functionInfo(node, name) };
      case "class":
      case "class_declaration":
        return { kind: "class", node, info: this };
      case "object": {
        const members = new Map<string, Entity>();
        for (const child of node.namedChildren) {
          if (child.type === "pair") {
            const key = child.childForFieldName("key");
            const value = child.childForFieldName("value");
            if (!key || !value) continue;
            const keyName = key.type === "string" ? stringValue(key) : key.type === "computed_property_name" ? undefined : key.text;
            const entity = keyName ? this.entityFromExpr(value, keyName) : undefined;
            if (keyName && entity) members.set(keyName, entity);
          } else if (child.type === "method_definition") {
            const methodName = child.childForFieldName("name")?.text;
            if (methodName) members.set(methodName, { kind: "fn", fn: this.functionInfo(child, methodName) });
          } else if (child.type === "shorthand_property_identifier") {
            members.set(child.text, { kind: "ref", name: child.text, at: { info: this, node: child } });
          }
        }
        return { kind: "obj", members };
      }
      case "identifier":
        return { kind: "ref", name: node.text, at: { info: this, node } };
      case "this":
        return this.thisEntity(node);
      case "member_expression": {
        const object = node.childForFieldName("object");
        const property = node.childForFieldName("property");
        if (!object || !property) return undefined;
        const objectEntity = this.entityFromExpr(object);
        return objectEntity ? { kind: "member", object: objectEntity, name: property.text } : undefined;
      }
      case "new_expression": {
        const constructorNode = node.childForFieldName("constructor");
        const constructorEntity = constructorNode ? this.entityFromExpr(constructorNode) : undefined;
        return constructorEntity ? { kind: "instance", of: constructorEntity } : undefined;
      }
      case "call_expression": {
        const spec = requireSpecifier(node);
        return spec ? { kind: "import", spec, name: "*", info: this } : undefined;
      }
      default:
        return undefined;
    }
  }

  /** What `this` is at `node`: the enclosing class's instance, constructor function's instance, or object literal. */
  thisEntity(node: SyntaxNode): Entity | undefined {
    for (let current = node.parent; current; current = current.parent) {
      switch (current.type) {
        case "arrow_function":
          continue;
        case "function_expression":
        case "function": {
          const parent = current.parent;
          if (parent?.type === "assignment_expression" && parent.childForFieldName("left")?.text.startsWith("this.")) continue;
          if (parent?.type === "pair" && parent.parent?.type === "object") return this.entityFromExpr(parent.parent);
          return undefined;
        }
        case "method_definition": {
          const owner = current.parent?.parent;
          if (current.parent?.type === "class_body" && owner) return { kind: "instance", of: { kind: "class", node: owner, info: this } };
          if (current.parent?.type === "object") return this.entityFromExpr(current.parent);
          return undefined;
        }
        case "function_declaration":
          return { kind: "instance", of: { kind: "fn", fn: this.functionInfo(current) } };
        case "class_body":
          return current.parent ? { kind: "instance", of: { kind: "class", node: current.parent, info: this } } : undefined;
        default:
          continue;
      }
    }
    return undefined;
  }

  // ---- members of classes / constructor functions ------------------------

  /** Methods of a class: instance ones (`wantStatic: false`, with inheritance) or `static` ones. */
  classMembers(node: SyntaxNode, wantStatic: boolean, depth = 0): Map<string, Entity> {
    const key = `class:${rangeKey(node)}:${wantStatic}`;
    const cached = this.memberCache.get(key);
    if (cached) return cached;
    const members = new Map<string, Entity>();
    this.memberCache.set(key, members);

    if (!wantStatic && depth < 4) {
      const heritage = node.namedChildren.find((c) => c.type === "class_heritage");
      const extendsClause = heritage?.namedChildren.find((c) => c.type === "extends_clause");
      const parentExpr = extendsClause ? (extendsClause.childForFieldName("value") ?? extendsClause.namedChild(0)) : heritage?.namedChild(0);
      const parentEntity = parentExpr ? this.entityFromExpr(parentExpr) : undefined;
      const parent = this.project.resolve(parentEntity);
      if (parent?.kind === "class") {
        for (const [k, v] of parent.info.classMembers(parent.node, false, depth + 1)) members.set(k, v);
      }
    }

    const body = node.childForFieldName("body");
    for (const member of body?.namedChildren ?? []) {
      if (isStatic(member) !== wantStatic) continue;
      if (member.type === "method_definition") {
        const name = member.childForFieldName("name")?.text;
        if (name) members.set(name, { kind: "fn", fn: this.functionInfo(member, name) });
      } else if (member.type === "field_definition" || member.type === "public_field_definition") {
        const name = (member.childForFieldName("property") ?? member.childForFieldName("name"))?.text;
        const value = member.childForFieldName("value");
        const entity = name && value ? this.entityFromExpr(value, name) : undefined;
        if (name && entity) members.set(name, entity);
      }
    }
    return members;
  }

  /** `function Dao(db) { this.find = function (x) {...} }` and `Dao.prototype.find = ...` */
  constructorInstanceMembers(fn: FunctionInfo): Map<string, Entity> {
    const key = `ctor:${rangeKey(fn.node)}`;
    const cached = this.memberCache.get(key);
    if (cached) return cached;
    const members = new Map<string, Entity>();
    this.memberCache.set(key, members);

    const assignments: SyntaxNode[] = [];
    if (fn.body) collectThisAssignments(fn.body, assignments);
    for (const assignment of assignments) {
      const property = assignment.childForFieldName("left")?.childForFieldName("property");
      const right = assignment.childForFieldName("right");
      const entity = property && right ? this.entityFromExpr(right, property.text) : undefined;
      if (property && entity) members.set(property.text, entity);
    }
    for (const [k, v] of this.assignedMembers(fn, `${fn.name}.prototype`)) members.set(k, v);
    return members;
  }

  /** `fn.helper = function () {}` (static-style members of a function). */
  constructorStaticMembers(fn: FunctionInfo): Map<string, Entity> {
    const key = `static:${rangeKey(fn.node)}`;
    const cached = this.memberCache.get(key);
    if (cached) return cached;
    const members = this.assignedMembers(fn, fn.name);
    this.memberCache.set(key, members);
    return members;
  }

  /** Assignments `<prefix>.x = value` in the scope that declares `fn`. */
  private assignedMembers(fn: FunctionInfo, prefix: string): Map<string, Entity> {
    const members = new Map<string, Entity>();
    let scope: SyntaxNode | null = fn.node.parent;
    while (scope && scope.type !== "program" && scope.type !== "statement_block") scope = scope.parent;
    for (const statement of scope?.namedChildren ?? []) {
      const expression = statement.type === "expression_statement" ? statement.namedChild(0) : null;
      if (expression?.type !== "assignment_expression") continue;
      const left = expression.childForFieldName("left");
      const right = expression.childForFieldName("right");
      if (left?.type !== "member_expression" || !right) continue;
      const object = left.childForFieldName("object");
      const property = left.childForFieldName("property");
      if (object?.text !== prefix || !property) continue;
      const entity = this.entityFromExpr(right, property.text);
      if (entity) members.set(property.text, entity);
    }
    return members;
  }

  // ---- exports -----------------------------------------------------------

  private exports(): ModuleExports {
    if (this.exportsCache) return this.exportsCache;
    const result: ModuleExports = { named: new Map(), stars: [] };
    this.exportsCache = result;

    for (const statement of this.root.namedChildren) {
      if (statement.type === "export_statement") {
        this.collectExportStatement(statement, result);
      } else if (statement.type === "expression_statement") {
        const expression = statement.namedChild(0);
        if (expression?.type !== "assignment_expression") continue;
        const left = expression.childForFieldName("left");
        const right = expression.childForFieldName("right");
        if (!left || !right) continue;
        if (left.text === "module.exports") {
          result.commonjs = this.entityFromExpr(right);
          continue;
        }
        const match = /^(?:module\.)?exports\.(\w+)$/.exec(left.text);
        const entity = match ? this.entityFromExpr(right, match[1]) : undefined;
        if (match?.[1] && entity) result.named.set(match[1], entity);
      }
    }
    return result;
  }

  private collectExportStatement(statement: SyntaxNode, result: ModuleExports): void {
    const source = statement.childForFieldName("source");
    const spec = source ? stringValue(source) : undefined;
    const declaration = statement.childForFieldName("declaration");
    const value = statement.childForFieldName("value");
    const isDefault = statement.children.some((c) => c.type === "default");

    if (declaration) {
      if (isDefault) {
        result.defaultExport = this.entityFromExpr(declaration, "default");
        return;
      }
      if (declaration.type === "function_declaration" || declaration.type === "class_declaration") {
        const name = declaration.childForFieldName("name")?.text;
        const entity = this.entityFromExpr(declaration);
        if (name && entity) result.named.set(name, entity);
      } else {
        for (const declarator of declaration.namedChildren) {
          const nameNode = declarator.childForFieldName("name");
          const init = declarator.childForFieldName("value");
          const entity = nameNode?.type === "identifier" && init ? this.entityFromExpr(init, nameNode.text) : undefined;
          if (nameNode && entity) result.named.set(nameNode.text, entity);
        }
      }
      return;
    }
    if (value && isDefault) {
      result.defaultExport = this.entityFromExpr(value, "default");
      return;
    }
    const clause = statement.namedChildren.find((c) => c.type === "export_clause");
    if (!clause) {
      if (spec) result.stars.push(spec); // export * from "./x"
      return;
    }
    for (const specifier of clause.namedChildren) {
      if (specifier.type !== "export_specifier") continue;
      const name = specifier.childForFieldName("name")?.text;
      const alias = specifier.childForFieldName("alias")?.text;
      if (!name) continue;
      result.named.set(
        alias ?? name,
        spec ? { kind: "import", spec, name, info: this } : { kind: "ref", name, at: { info: this, node: specifier } },
      );
    }
  }

  /** What `require("./thisfile")` / `import * as x from "./thisfile"` gives you. */
  moduleObject(): Entity {
    const exports = this.exports();
    if (exports.commonjs) return exports.commonjs;
    const members = new Map(exports.named);
    if (exports.defaultExport) members.set("default", exports.defaultExport);
    return { kind: "obj", members };
  }

  exportOf(name: string, depth = 0): Entity | undefined {
    const exports = this.exports();
    if (name === "*") return this.moduleObject();
    if (name === "default") return exports.defaultExport ?? exports.commonjs;
    const direct = exports.named.get(name);
    if (direct) return direct;
    if (exports.commonjs) {
      const fromCommonjs = this.project.membersOf(this.project.resolve(exports.commonjs))?.get(name);
      if (fromCommonjs) return fromCommonjs;
    }
    if (depth < 3) {
      for (const spec of exports.stars) {
        const target = this.project.resolveModule(this.file, spec);
        const info = target ? this.project.fileInfo(target) : undefined;
        const found = info?.exportOf(name, depth + 1);
        if (found) return found;
      }
    }
    return undefined;
  }
}

interface AliasRule {
  prefix: string;
  targets: string[];
}

export interface ProjectContextOptions {
  /** Read other files from disk to follow imports. Off for in-memory scans. */
  allowDisk?: boolean;
}

export class ProjectContext {
  readonly root: string;
  private readonly allowDisk: boolean;
  private readonly files = new Map<string, FileInfo>();
  private readonly moduleCache = new Map<string, string | undefined>();
  private readonly isFileCache = new Map<string, boolean>();
  private aliases?: AliasRule[];

  /** Per-rule "which parameters reach a sink" memo (see interprocedural.ts). */
  readonly summaries = new Map<string, Map<number, unknown>>();
  readonly summarizing = new Set<string>();

  private static readonly singleFile = new WeakMap<ParsedFile, ProjectContext>();

  constructor(root: string, options: ProjectContextOptions = {}) {
    this.root = path.resolve(root);
    this.allowDisk = options.allowDisk ?? true;
  }

  /** A context that knows only `parsed` — same-file helper calls resolve, imports don't. */
  static forSingleFile(file: string, parsed: ParsedFile): ProjectContext {
    const cached = ProjectContext.singleFile.get(parsed);
    if (cached) return cached;
    const context = new ProjectContext(path.dirname(path.resolve(file)), { allowDisk: false });
    context.fileInfo(file, parsed);
    ProjectContext.singleFile.set(parsed, context);
    return context;
  }

  /** A parse of `file` we already hold for exactly this source, so a scan never parses a file twice. */
  cachedParse(file: string, sourceCode: string): ParsedFile | undefined {
    const info = this.files.get(path.resolve(file));
    return info && info.parsed.sourceCode === sourceCode ? info.parsed : undefined;
  }

  fileInfo(file: string, parsed?: ParsedFile): FileInfo | undefined {
    const key = path.resolve(file);
    const cached = this.files.get(key);
    if (cached) {
      this.files.delete(key); // refresh LRU position
      this.files.set(key, cached);
      return cached;
    }
    let source = parsed;
    if (!source) {
      if (!this.allowDisk || !languageForExtension(path.extname(key))) return undefined;
      try {
        source = parseFile(key, fs.readFileSync(key, "utf8"));
      } catch {
        return undefined;
      }
      if (!source) return undefined;
    }
    const info = new FileInfo(this, key, source);
    this.files.set(key, info);
    if (this.files.size > MAX_CACHED_FILES) {
      const oldest = this.files.keys().next().value;
      if (oldest !== undefined) this.files.delete(oldest);
    }
    return info;
  }

  displayPath(file: string): string {
    return path.relative(this.root, file).split(path.sep).join("/") || path.basename(file);
  }

  // ---- module resolution ---------------------------------------------------

  private isFile(candidate: string): boolean {
    const cached = this.isFileCache.get(candidate);
    if (cached !== undefined) return cached;
    let result = false;
    try {
      result = fs.statSync(candidate).isFile();
    } catch {
      result = false;
    }
    this.isFileCache.set(candidate, result);
    return result;
  }

  private loadAliases(): AliasRule[] {
    if (this.aliases) return this.aliases;
    const rules: AliasRule[] = [];
    // tsconfig.json / jsconfig.json "paths" (searched upward: the scanned folder may be a sub-folder of the project).
    let dir = this.root;
    for (let i = 0; i < 5; i++) {
      const configPath = ["tsconfig.json", "jsconfig.json"].map((n) => path.join(dir, n)).find((p) => this.isFile(p));
      if (configPath) {
        try {
          const text = stripJsonComments(fs.readFileSync(configPath, "utf8")).replace(/,(\s*[}\]])/g, "$1");
          const options = JSON.parse(text).compilerOptions ?? {};
          const baseUrl = path.resolve(dir, options.baseUrl ?? ".");
          for (const [pattern, targets] of Object.entries<string[]>(options.paths ?? {})) {
            if (!pattern.endsWith("*")) continue;
            rules.push({
              prefix: pattern.slice(0, -1),
              targets: targets.filter((t) => t.endsWith("*")).map((t) => path.resolve(baseUrl, t.slice(0, -1))),
            });
          }
          if (options.baseUrl) rules.push({ prefix: "", targets: [baseUrl] });
        } catch {
          // an unreadable config just means no aliases
        }
        break;
      }
      const parent = path.dirname(dir);
      if (parent === dir) break;
      dir = parent;
    }
    // The conventional `@/` and `~/` aliases (Next.js, Vite) even without a config.
    rules.push({ prefix: "@/", targets: [this.root, path.join(this.root, "src")] });
    rules.push({ prefix: "~/", targets: [this.root, path.join(this.root, "src")] });
    this.aliases = rules;
    return rules;
  }

  resolveModule(fromFile: string, spec: string): string | undefined {
    if (!this.allowDisk) return undefined;
    const cacheKey = `${path.dirname(fromFile)}|${spec}`;
    if (this.moduleCache.has(cacheKey)) return this.moduleCache.get(cacheKey);

    let bases: string[] = [];
    if (spec.startsWith(".")) {
      bases = [path.resolve(path.dirname(fromFile), spec)];
    } else {
      for (const rule of this.loadAliases()) {
        if (rule.prefix === "" ? spec.includes("/") : spec.startsWith(rule.prefix)) {
          bases.push(...rule.targets.map((t) => path.join(t, spec.slice(rule.prefix.length))));
        }
      }
    }

    let found: string | undefined;
    outer: for (const base of bases) {
      const candidates = [base, ...EXTENSIONS.map((e) => base + e), ...EXTENSIONS.map((e) => path.join(base, `index${e}`))];
      if (/\.[cm]?js$/.test(base)) candidates.push(base.replace(/\.[cm]?js$/, ".ts"), base.replace(/\.[cm]?js$/, ".tsx"));
      for (const candidate of candidates) {
        if (this.isFile(candidate)) {
          found = candidate;
          break outer;
        }
      }
    }
    this.moduleCache.set(cacheKey, found);
    return found;
  }

  // ---- entity resolution ---------------------------------------------------

  /** Follows refs, member accesses and imports until it reaches a concrete function / object / class / instance. */
  resolve(entity: Entity | undefined, depth = 0): Entity | undefined {
    let current = entity;
    for (let step = depth; current && step < MAX_RESOLVE_DEPTH; step++) {
      switch (current.kind) {
        case "ref":
          current = current.at.info.lookup(current.name, current.at.node);
          break;
        case "member":
          current = this.membersOf(this.resolve(current.object, step + 1))?.get(current.name);
          break;
        case "import": {
          const target = this.resolveModule(current.info.file, current.spec);
          const info = target ? this.fileInfo(target) : undefined;
          current = info?.exportOf(current.name);
          break;
        }
        case "instance": {
          const of = this.resolve(current.of, step + 1);
          return of ? { kind: "instance", of } : undefined;
        }
        default:
          return current;
      }
    }
    return undefined;
  }

  /** The named members reachable on an already-resolved entity. */
  membersOf(entity: Entity | undefined): Map<string, Entity> | undefined {
    if (!entity) return undefined;
    switch (entity.kind) {
      case "obj":
        return entity.members;
      case "class":
        return entity.info.classMembers(entity.node, true);
      case "fn":
        return entity.fn.info.constructorStaticMembers(entity.fn);
      case "instance": {
        const of = entity.of;
        if (of.kind === "class") return of.info.classMembers(of.node, false);
        if (of.kind === "fn") return of.fn.info.constructorInstanceMembers(of.fn);
        if (of.kind === "obj") return of.members;
        return undefined;
      }
      default:
        return undefined;
    }
  }

  /**
   * The project function a call or `new` expression runs, if it can be determined.
   * `new Foo(x)` resolves to the class's `constructor` / the constructor function itself.
   */
  resolveCallee(call: SyntaxNode, info: FileInfo): FunctionInfo | undefined {
    const isNew = call.type === "new_expression";
    const calleeNode = call.childForFieldName(isNew ? "constructor" : "function");
    if (!calleeNode) return undefined;
    const callee = unwrap(calleeNode);
    let entity: Entity | undefined;
    if (callee.type === "identifier") entity = info.lookup(callee.text, call);
    else if (callee.type === "member_expression") entity = info.entityFromExpr(callee);
    else return undefined;

    const resolved = this.resolve(entity);
    if (resolved?.kind === "fn") return resolved.fn;
    if (isNew && resolved?.kind === "class") {
      const ctor = resolved.info.classMembers(resolved.node, false).get("constructor");
      return ctor?.kind === "fn" ? ctor.fn : undefined;
    }
    return undefined;
  }
}
