import * as path from "path";
import { ParsedFile } from "../parsers/ast-parser";
import { SyntaxNode, findNodes, snippet, toLocation } from "../parsers/utils";
import { ProjectContext } from "../taint/project";
import { Finding } from "../types";
import { findViewTemplate, UnsafeUse, viewUnsafeUse } from "../templates";
import { Analyzer } from "./base-analyzer";
import { dataEntries, renderCall } from "./template-xss";

/**
 * Stored XSS: text that a visitor saved earlier (a comment, a memo, a display name) is read back from the database and handed to a view that
 * prints it raw. The request is not in sight, so the data-flow rules cannot see it; this rule follows the database instead:
 *
 *   const posts = await Post.find();                       // a model, a pool, a DAO, prisma, knex, mongoose, supabase ...
 *   memosDAO.getAllMemos((err, docs) => res.render("memos", { memosList: docs }));
 *   db.query(sql).then((rows) => res.render("list", { rows }));
 *
 * and reports it when the view prints that key (or what a loop over it holds) without escaping: EJS \`<%- %>\`, Pug \`!{}\`, Handlebars
 * \`{{{ }}}\`, \`| safe\`, or a plain \`{{ }}\` while the engine's escaping is off. Reported with LOW confidence: whether anyone can store markup
 * in that column is the application's design, which a scanner cannot see.
 */

const FUNCTION_LIKE = new Set(["function_declaration", "function_expression", "function", "arrow_function", "method_definition", "generator_function", "generator_function_declaration"]);
const DB_METHOD = /^(?:find|findAll|findOne|findMany|findFirst|findUnique|findById|findByPk|findOneBy|findBy|findAndCountAll|aggregate|query|execute|select|all|toArray|exec|raw|fetchAll|getMany|getOne|populate|lean)$/;
const DB_RECEIVER = /(?:^|\.)(?:db|database|pool|conn|connection|client|prisma|knex|sequelize|mongoose|collection|repo|repository|store|dao|orm|supabase|firestore|sql|models?|em|entityManager)(?:$|\.|\()/i;
const DAO_METHOD = /^(?:get|find|fetch|load|list|select|read|query|search)[A-Z_]\w*$/;
const DAO_RECEIVER = /dao|repo|repository|store|model|db|database|service|manager/i;
const NOT_A_MODEL = new Set(["Array", "Object", "String", "Promise", "JSON", "Math", "Map", "Set", "Number", "Date", "Buffer", "Symbol", "Reflect", "Intl", "URL", "Boolean", "Error"]);

function unwrap(node: SyntaxNode | null | undefined): SyntaxNode | null {
  let current = node ?? null;
  while (current && (current.type === "await_expression" || current.type === "parenthesized_expression")) current = current.namedChild(0);
  return current;
}

/** The calls along a chain like `Post.find().populate("author").lean()`. */
function chainCalls(node: SyntaxNode | null): SyntaxNode[] {
  const out: SyntaxNode[] = [];
  let current = unwrap(node);
  while (current) {
    if (current.type === "call_expression") {
      out.push(current);
      current = unwrap(current.childForFieldName("function"));
    } else if (current.type === "member_expression") {
      current = unwrap(current.childForFieldName("object"));
    } else {
      break;
    }
  }
  return out;
}

function isDbCall(call: SyntaxNode): boolean {
  const callee = call.childForFieldName("function");
  if (callee?.type !== "member_expression") return false;
  const method = callee.childForFieldName("property")?.text ?? "";
  const receiver = callee.childForFieldName("object")?.text ?? "";
  const last = receiver.split(".").pop() ?? "";
  if (DB_METHOD.test(method) && (DB_RECEIVER.test(receiver) || (/^[A-Z]\w*$/.test(last) && !NOT_A_MODEL.has(last)))) return true;
  return DAO_METHOD.test(method) && DAO_RECEIVER.test(last);
}

function fromDatabase(node: SyntaxNode | null | undefined): boolean {
  return chainCalls(node ?? null).some(isDbCall);
}

function boundIdentifiers(pattern: SyntaxNode | null | undefined): string[] {
  if (!pattern) return [];
  if (pattern.type === "identifier" || pattern.type === "shorthand_property_identifier_pattern") return [pattern.text];
  return findNodes(pattern, (n) => n.type === "identifier" || n.type === "shorthand_property_identifier_pattern").map((n) => n.text);
}

/** Root identifier of `docs`, `docs.rows`, `docs[0].name`, `rows.map(...)`. */
function rootIdentifier(node: SyntaxNode | null | undefined): string | undefined {
  let current = unwrap(node);
  while (current && (current.type === "member_expression" || current.type === "subscript_expression" || current.type === "call_expression")) {
    current = unwrap(current.type === "call_expression" ? current.childForFieldName("function") : (current.childForFieldName("object") ?? current.namedChild(0)));
  }
  return current?.type === "identifier" ? current.text : undefined;
}

/** Names that hold database rows inside (or around) this function. */
function databaseNames(fn: SyntaxNode): Set<string> {
  const names = new Set<string>();
  // a callback handed to a database call: (err, rows) => ... / rows => ... (.then)
  const owner = fn.parent?.type === "arguments" ? fn.parent.parent : undefined;
  if (owner?.type === "call_expression") {
    const callee = owner.childForFieldName("function");
    const viaThen = callee?.type === "member_expression" && callee.childForFieldName("property")?.text === "then" && fromDatabase(callee.childForFieldName("object"));
    if (isDbCall(owner) || viaThen) {
      const params = (fn.childForFieldName("parameters")?.namedChildren ?? [fn.childForFieldName("parameter")].filter((p): p is SyntaxNode => !!p)).flatMap((p) => boundIdentifiers(p));
      const [first, ...rest] = params;
      for (const name of first && /^(?:err|error|e)$/i.test(first) ? rest.slice(0, 1) : params.slice(0, 1)) names.add(name);
    }
  }
  const body = fn.childForFieldName("body");
  if (!body) return names;
  for (let pass = 0; pass < 2; pass++) {
    for (const declaration of findNodes(body, (n) => n.type === "variable_declarator")) {
      const init = declaration.childForFieldName("value");
      const root = rootIdentifier(init);
      if (fromDatabase(init) || (root && names.has(root))) for (const name of boundIdentifiers(declaration.childForFieldName("name"))) names.add(name);
    }
    for (const assignment of findNodes(body, (n) => n.type === "assignment_expression")) {
      const right = assignment.childForFieldName("right");
      const root = rootIdentifier(right);
      const left = assignment.childForFieldName("left");
      if (left?.type === "identifier" && (fromDatabase(right) || (root && names.has(root)))) names.add(left.text);
    }
  }
  return names;
}

function enclosingFunctions(node: SyntaxNode, limit = 4): SyntaxNode[] {
  const out: SyntaxNode[] = [];
  for (let p: SyntaxNode | null = node.parent; p && out.length < limit; p = p.parent) if (FUNCTION_LIKE.has(p.type)) out.push(p);
  return out;
}

export class StoredXssAnalyzer implements Analyzer {
  analyze(parsed: ParsedFile, filePath: string, context?: ProjectContext): Finding[] {
    const text = parsed.sourceCode;
    if (!/\.render\s*\(|\.view\s*\(/.test(text)) return [];
    const root = context?.root ?? path.dirname(filePath);
    const display = (file: string): string => (context ? context.displayPath(file) : path.relative(root, file));
    const findings: Finding[] = [];
    const seen = new Set<number>();

    for (const call of findNodes(parsed.tree.rootNode, (n) => n.type === "call_expression")) {
      const render = renderCall(call);
      if (!render || seen.has(call.startIndex)) continue;
      const view = findViewTemplate(root, render.view);
      if (!view) continue;
      const names = new Set<string>();
      for (const fn of enclosingFunctions(call)) for (const name of databaseNames(fn)) names.add(name);
      if (names.size === 0) continue;

      const uses: Array<{ key: string; name: string; use: UnsafeUse }> = [];
      for (const { key, value } of dataEntries(render.data)) {
        const used = [...new Set(findNodes(value, (n) => n.type === "identifier" || n.type === "shorthand_property_identifier").map((n) => n.text).concat(value.type === "shorthand_property_identifier" ? [value.text] : []))].find((n) => names.has(n));
        if (!used) continue;
        const use = viewUnsafeUse(view, key, root);
        if (use) uses.push({ key, name: used, use });
      }
      const first = uses[0];
      if (!first) continue;
      seen.add(call.startIndex);
      findings.push({
        ruleId: "xss",
        severity: "high",
        confidence: "low",
        message:
          `\`${first.name}\` was read from the database and is handed to the view as \`${first.key}\`, which prints it without escaping (${display(first.use.file)}:${first.use.line}, ${first.use.how}). ` +
          `If any visitor can store text there (a comment, a memo, a name, a profile field) this is stored XSS: a value with <script> runs in the browser of everyone who opens the page. ` +
          `Print it with the escaping tag (<%= %> in EJS, #{} in Pug, {{ }} in Handlebars; keep the engine's escaping on), or sanitise rich text with DOMPurify before saving it.`,
        location: toLocation(call, filePath),
        sourceSnippet: `${first.name} (database)`,
        sinkSnippet: snippet(call, text),
      });
    }
    return findings;
  }
}
