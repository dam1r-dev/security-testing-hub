import * as fs from "fs";
import * as path from "path";
import { SyntaxNode } from "../parsers/utils";
import { TextEdit } from "./types";

/**
 * Turns `db.query(\`SELECT * FROM users WHERE id = ${id} AND name = '${name}'\`)` into
 * `db.query(\`SELECT * FROM users WHERE id = $1 AND name = $2\`, [id, name])`: the values travel separately from the SQL,
 * so they can never change what the query means.
 *
 * Only done where it is mechanical and certain: a single template literal or `+` chain, a known driver (so the
 * placeholder style is right), values in value positions. A name used as a table or column (`FROM ${table}`,
 * `ORDER BY ${col}`, `user_${id}`), an expanded list (`IN (${ids.join(",")})`) or a query that already has a values
 * array is left to a person: those need an allowlist or a different query, not a placeholder.
 */

const SQL_CALLEES = new Set(["query", "execute", "all", "get", "run", "raw"]);
const NUMBERED = /^(?:pg|postgres|pg-promise|@vercel\/postgres|@neondatabase\/serverless|@supabase\/postgres-js)$/;
const QUESTION = /^(?:mysql|mysql2|sqlite3|better-sqlite3|@libsql\/client|knex|mariadb|sqlite)$/;
const NAME_POSITION = /(?:\bfrom|\bjoin|\binto|\bupdate|\btable|\bby|\bas|\blimit|\boffset|\bcolumn|\basc|\bdesc|\bon|\bset)\s*$/i;
const MARK = "\u0000";

export type PlaceholderStyle = "numbered" | "question";

/** Which placeholder style the project's SQL driver uses, from the nearest package.json. */
export function placeholderStyle(file: string): PlaceholderStyle | undefined {
  let dir = path.dirname(path.resolve(file));
  for (let depth = 0; depth < 10; depth++) {
    const candidate = path.join(dir, "package.json");
    if (fs.existsSync(candidate)) {
      try {
        const pkg = JSON.parse(fs.readFileSync(candidate, "utf8"));
        const deps = Object.keys({ ...pkg.dependencies, ...pkg.devDependencies });
        const numbered = deps.some((d) => NUMBERED.test(d));
        const question = deps.some((d) => QUESTION.test(d));
        if (numbered && !question) return "numbered";
        if (question && !numbered) return "question";
      } catch {
        return undefined;
      }
      return undefined;
    }
    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return undefined;
}

export interface Flat {
  /** SQL text with a MARK + index + MARK where each JS expression was. */
  sql: string;
  expressions: string[];
  /** The text is a template literal (kept as one) or a concatenation (rewritten as a plain string). */
  template: boolean;
}

function cook(raw: string): string | undefined {
  // only the escapes that cannot change meaning; anything else is left to a person
  if (/\\(?![\\'"`nrt])/.test(raw)) return undefined;
  const named: Record<string, string> = { n: "\n", r: "\r", t: "\t" };
  return raw.replace(/\\(.)/g, (_match, ch: string) => named[ch] ?? ch);
}

function flattenTemplate(node: SyntaxNode): Flat | undefined {
  let sql = "";
  const expressions: string[] = [];
  for (const child of node.namedChildren) {
    if (child.type === "string_fragment" || child.type === "escape_sequence") sql += child.text;
    else if (child.type === "template_substitution") {
      const expression = child.namedChild(0);
      if (!expression) return undefined;
      sql += `${MARK}${expressions.length}${MARK}`;
      expressions.push(expression.text);
    } else if (child.type !== "comment") return undefined;
  }
  return { sql, expressions, template: true };
}

function flattenConcatenation(node: SyntaxNode): Flat | undefined {
  const operands: SyntaxNode[] = [];
  const collect = (n: SyntaxNode): boolean => {
    if (n.type === "binary_expression" && n.childForFieldName("operator")?.text === "+") {
      const left = n.childForFieldName("left");
      const right = n.childForFieldName("right");
      return !!left && !!right && collect(left) && collect(right);
    }
    if (n.type === "parenthesized_expression" && n.namedChild(0)?.type === "binary_expression") return collect(n.namedChild(0) as SyntaxNode);
    operands.push(n);
    return true;
  };
  if (!collect(node)) return undefined;
  let sql = "";
  const expressions: string[] = [];
  for (const operand of operands) {
    if (operand.type === "string") {
      const cooked = cook(operand.text.slice(1, -1));
      if (cooked === undefined || cooked.includes(MARK)) return undefined;
      sql += cooked;
    } else if (operand.type === "template_string" && !operand.namedChildren.some((c) => c.type === "template_substitution")) {
      const cooked = cook(operand.text.slice(1, -1));
      if (cooked === undefined) return undefined;
      sql += cooked;
    } else {
      sql += `${MARK}${expressions.length}${MARK}`;
      expressions.push(operand.type === "binary_expression" ? `(${operand.text})` : operand.text);
    }
  }
  if (expressions.length === 0) return undefined;
  return { sql, expressions, template: false };
}

const escapeForTemplate = (text: string): string => text.replace(/\\/g, "\\\\").replace(/`/g, "\\`").replace(/\$\{/g, "\\${");

function paramFor(content: string, expressions: string[]): string {
  const pieces = content.replace(/''/g, "'").split(MARK);
  // pieces = [text, index, text, index, ..., text]
  if (pieces.length === 3 && pieces[0] === "" && pieces[2] === "") return expressions[Number(pieces[1])] as string;
  let template = "`";
  for (let i = 0; i < pieces.length; i++) {
    template += i % 2 === 0 ? escapeForTemplate(pieces[i] as string) : `\${${expressions[Number(pieces[i])]}}`;
  }
  return `${template}\``;
}

/** `{ sql, params }` with placeholders, or the reason it cannot be done safely. */
export function parameterizeSql(flat: Flat, style: PlaceholderStyle): { sql: string; params: string[] } | { reason: string } {
  const s = flat.sql;
  let out = "";
  const params: string[] = [];
  const placeholder = (): string => (style === "numbered" ? `$${params.length}` : "?");
  let i = 0;
  while (i < s.length) {
    const c = s[i] as string;
    if (c === "'") {
      let j = i + 1;
      let content = "";
      for (;;) {
        if (j >= s.length) return { reason: "a quote is not closed inside the text, so the values cannot be told apart from the SQL" };
        if (s[j] === "'") {
          if (s[j + 1] === "'") {
            content += "''";
            j += 2;
            continue;
          }
          break;
        }
        content += s[j];
        j++;
      }
      if (content.includes(MARK)) {
        const expressionCodes = [...content.matchAll(new RegExp(`${MARK}(\\d+)${MARK}`, "g"))].map((m) => flat.expressions[Number(m[1])] as string);
        if (expressionCodes.some((code) => /\.join\(/.test(code))) return { reason: "a list is joined into the text (IN (...)); it needs one placeholder per item" };
        params.push(paramFor(content, flat.expressions));
        out += placeholder();
      } else {
        out += `'${content}'`;
      }
      i = j + 1;
    } else if (c === '"' ) {
      // a double-quoted name (identifier) with a value inside cannot be a placeholder
      const end = s.indexOf('"', i + 1);
      if (end === -1) return { reason: "a double quote is not closed inside the text" };
      const inside = s.slice(i, end + 1);
      if (inside.includes(MARK)) return { reason: "a value is used inside a quoted name (table or column), which cannot be a placeholder" };
      out += inside;
      i = end + 1;
    } else if (c === MARK) {
      const end = s.indexOf(MARK, i + 1);
      const index = Number(s.slice(i + 1, end));
      const code = flat.expressions[index] as string;
      if (NAME_POSITION.test(out)) return { reason: "a value is used where SQL expects a table or column name (FROM / ORDER BY / LIMIT ...): check it against an allowlist instead" };
      if (/[\w.$"`]$/.test(out) || /^[\w."]/.test(s.slice(end + 1))) return { reason: "a value is glued to other text (user_${id}), so it is part of a name, not a value" };
      if (/\.join\(/.test(code)) return { reason: "a list is joined into the text (IN (...)); it needs one placeholder per item" };
      params.push(code);
      out += placeholder();
      i = end + 1;
    } else {
      out += c;
      i++;
    }
  }
  if (params.length === 0) return { reason: "no value was found to move out of the text" };
  return { sql: out, params };
}

/** `db.query(sql).then(...).catch(...)`: the query call at the start of a promise chain. */
function queryCallOf(call: SyntaxNode): SyntaxNode {
  let current = call;
  for (;;) {
    const callee = current.childForFieldName("function");
    const object = callee?.type === "member_expression" ? callee.childForFieldName("object") : undefined;
    const method = callee?.type === "member_expression" ? callee.childForFieldName("property")?.text : undefined;
    if (object?.type === "call_expression" && (method === "then" || method === "catch" || method === "finally")) current = object;
    else return current;
  }
}

/** Does the nearest package.json list a dependency matching `pattern`? */
export function hasDependency(file: string, pattern: RegExp): boolean {
  let dir = path.dirname(path.resolve(file));
  for (let depth = 0; depth < 10; depth++) {
    const candidate = path.join(dir, "package.json");
    if (fs.existsSync(candidate)) {
      try {
        const pkg = JSON.parse(fs.readFileSync(candidate, "utf8"));
        return Object.keys({ ...pkg.dependencies, ...pkg.devDependencies }).some((d) => pattern.test(d));
      } catch {
        return false;
      }
    }
    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return false;
}

/** The edit that rewrites the SQL call `call`, or the reason it was left alone. */
export function sqlEdit(flagged: SyntaxNode, file: string, style: PlaceholderStyle | undefined): TextEdit | { reason: string } {
  if (flagged.type !== "call_expression") return { reason: "the flagged code is not a plain call" };
  const call = queryCallOf(flagged);
  // Sequelize takes bound values as { replacements: [...] } with ? placeholders, whatever the dialect
  const sequelize = /sequelize/i.test(call.childForFieldName("function")?.text ?? "") && hasDependency(file, /^sequelize$/);
  if (sequelize) style = "question";
  const callee = call.childForFieldName("function");
  const name = callee?.type === "member_expression" ? callee.childForFieldName("property")?.text : callee?.text;
  if (!name || !SQL_CALLEES.has(name)) return { reason: `${name ?? "this call"} is not a query call the fixer knows` };
  if (!style) return { reason: "the SQL driver was not recognised (the placeholder style is $1 for pg, ? for mysql / sqlite), so it is left to a person" };
  const argsNode = call.childForFieldName("arguments");
  const args = argsNode?.namedChildren.filter((a) => a.type !== "comment") ?? [];
  if (args.length !== 1) return { reason: "the call already passes a values array (or more than one argument)" };
  const arg = args[0] as SyntaxNode;
  const flat = arg.type === "template_string" ? flattenTemplate(arg) : flattenConcatenation(arg);
  if (!flat) return { reason: "the query text is not a single template literal or `+` chain of plain strings" };
  const result = parameterizeSql(flat, style);
  if ("reason" in result) return { reason: result.reason };

  const text = flat.template ? `\`${result.sql}\`` : JSON.stringify(result.sql);
  return {
    file,
    start: arg.startIndex,
    end: arg.endIndex,
    text: sequelize ? `${text}, { replacements: [${result.params.join(", ")}] }` : `${text}, [${result.params.join(", ")}]`,
    note: `moved ${result.params.length} value(s) out of the SQL text into bound parameters`,
  };
}
