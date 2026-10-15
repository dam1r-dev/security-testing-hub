import { ParsedFile } from "../parsers/ast-parser";
import { SyntaxNode, findNodes, isFunctionNode, snippet, toLocation } from "../parsers/utils";
import { ProjectContext } from "../taint/project";
import { Finding } from "../types";
import { Analyzer } from "./base-analyzer";

/**
 * Mass assignment: the WHOLE request body goes into a database write (`User.create(req.body)`,
 * `prisma.user.update({ where, data: body })`, `new User(req.body)`, `Object.assign(user, req.body)`). Whatever fields the
 * caller adds are written too: `role: "admin"`, `isAdmin: true`, `balance`, `price`, `ownerId`, `emailVerified`.
 *
 * Only the whole object counts: `const { name, email } = req.body; User.create({ name, email })` picks its fields and is fine.
 * Reported as a finding to look at (medium): it is only a hole when the model has a field the caller must not set, which
 * the scanner cannot see.
 */

// `req.body`, `request.body`, `ctx.request.body`, and the calls that read a whole body: `await request.json()`, `readBody(event)`.
const WHOLE_BODY_MEMBER = /^(?:req|request|ctx\.request|ctx|context)\.body$/;
const WHOLE_BODY_CALL = /^(?:(?:req|request|event\.request|evt\.request|c\.req|ctx\.request)\.json|readBody|readValidatedBody)$/;

// A database write: Mongoose / Prisma / Sequelize / Supabase / Drizzle / Knex style.
const WRITE_METHOD = /(?:^|\.)(?:create|createMany|update|updateMany|updateOne|upsert|insert|insertOne|insertMany|insertInto|findByIdAndUpdate|findOneAndUpdate|findOneAndReplace|replaceOne|values|set|setDoc|updateDoc|addDoc|bulkCreate|save)$/;
const DB_OBJECT = /prisma|\bdb\b|database|supabase|drizzle|knex|collection|model|repo|repository|firestore|\.from\(|\btrx?\b|\borm\b|\bsequelize\b/i;
const CAPITALISED_MODEL = /^[A-Z][A-Za-z0-9_]*$/;

// The field names that make a whole-body write dangerous when the body is untrusted. Used only to word the message.
const SENSITIVE_HINT = "role, isAdmin, balance, price, ownerId or emailVerified";

function isWholeBody(node: SyntaxNode, aliases: Set<string>): boolean {
  let current = node;
  while (current.type === "await_expression" || current.type === "parenthesized_expression") {
    const inner = current.namedChild(0);
    if (!inner) return false;
    current = inner;
  }
  if (current.type === "identifier") return aliases.has(current.text);
  if (current.type === "member_expression") return WHOLE_BODY_MEMBER.test(current.text);
  if (current.type === "call_expression") {
    const callee = current.childForFieldName("function")?.text ?? "";
    if (WHOLE_BODY_CALL.test(callee)) return true;
    // Object.fromEntries(formData) / Object.fromEntries(await request.formData()): every form field
    if (callee === "Object.fromEntries") {
      const arg = current.childForFieldName("arguments")?.namedChild(0);
      return !!arg && /formData|\.entries\(\)|searchParams/i.test(arg.text);
    }
  }
  return false;
}

/** Names bound to the whole body: `const body = await request.json()`, `const data = { ...body }`. */
function wholeBodyAliases(fn: SyntaxNode): Set<string> {
  const names = new Set<string>();
  const declarators = findNodes(fn, (n) => n.type === "variable_declarator");
  for (let pass = 0; pass < 3; pass++) {
    for (const d of declarators) {
      const name = d.childForFieldName("name");
      const value = d.childForFieldName("value");
      if (name?.type !== "identifier" || !value || names.has(name.text)) continue;
      const copied = value.type === "object" && value.namedChildren.length === 1 && value.namedChild(0)?.type === "spread_element";
      const source = copied ? value.namedChild(0)?.namedChild(0) : value;
      if (source && isWholeBody(source, names)) names.add(name.text);
    }
  }
  return names;
}

/** Is `arg` the whole body, or an object literal that carries it (`{ data: body }`, `{ ...body }`, `{ $set: body }`)? */
function carriesWholeBody(arg: SyntaxNode, aliases: Set<string>, depth = 0): SyntaxNode | undefined {
  if (isWholeBody(arg, aliases)) return arg;
  if (arg.type !== "object" || depth > 2) return undefined;
  for (const member of arg.namedChildren) {
    if (member.type === "spread_element") {
      const inner = member.namedChild(0);
      if (inner && isWholeBody(inner, aliases)) return inner;
    } else if (member.type === "pair") {
      const key = member.childForFieldName("key")?.text.replace(/^["'`]|["'`]$/g, "") ?? "";
      if (/^(?:where|filter|include|select|orderBy|query|conditions?)$/.test(key)) continue; // a filter is not the written data
      const value = member.childForFieldName("value");
      const hit = value ? carriesWholeBody(value, aliases, depth + 1) : undefined;
      if (hit) return hit;
    } else if (member.type === "shorthand_property_identifier" && aliases.has(member.text)) {
      return member;
    }
  }
  return undefined;
}

function isDatabaseWrite(call: SyntaxNode): boolean {
  const callee = call.childForFieldName("function");
  if (!callee || callee.type !== "member_expression") return false;
  if (!WRITE_METHOD.test(callee.text)) return false;
  const object = callee.childForFieldName("object");
  if (!object) return false;
  return DB_OBJECT.test(object.text) || CAPITALISED_MODEL.test(object.text);
}

// The body is trimmed or checked somewhere in the function before it is written.
const TRIMMED = /\bdelete\s+(?:req\.|request\.)?body\b|\bdelete\s+\w+\.(?:role|isAdmin|is_admin|admin)\b|\b(?:pick|omit|allowedFields|allowedKeys|permittedFields|whitelist|allowlist)\b|\.parse\(|\.safeParse\(|\.validate\(/;

export class MassAssignmentAnalyzer implements Analyzer {
  analyze(parsed: ParsedFile, filePath: string, _context?: ProjectContext): Finding[] {
    const text = parsed.sourceCode;
    if (!/\bbody\b|\.json\(|readBody|formData/.test(text)) return [];
    const findings: Finding[] = [];
    const seen = new Set<number>();

    for (const fn of findNodes(parsed.tree.rootNode, isFunctionNode)) {
      if (TRIMMED.test(fn.text)) continue;
      const aliases = wholeBodyAliases(fn);

      for (const node of findNodes(fn, (n) => n.type === "call_expression" || n.type === "new_expression")) {
        if (seen.has(node.startIndex)) continue;
        let target: SyntaxNode | undefined;
        let label: string;
        if (node.type === "new_expression") {
          const ctor = node.childForFieldName("constructor");
          if (!ctor || !CAPITALISED_MODEL.test(ctor.text)) continue;
          const arg = node.childForFieldName("arguments")?.namedChild(0);
          target = arg ? carriesWholeBody(arg, aliases) : undefined;
          label = `new ${ctor.text}(...)`;
        } else {
          const callee = node.childForFieldName("function")?.text ?? "";
          const args = node.childForFieldName("arguments")?.namedChildren ?? [];
          if (callee === "Object.assign" && args.length >= 2 && args[0]?.type !== "object") {
            target = args.slice(1).map((a) => carriesWholeBody(a, aliases)).find(Boolean);
            label = "Object.assign(...)";
          } else if (isDatabaseWrite(node)) {
            target = args.map((a) => carriesWholeBody(a, aliases)).find(Boolean);
            label = `${callee}(...)`;
          } else {
            continue;
          }
        }
        if (!target) continue;
        seen.add(node.startIndex);
        findings.push({
          ruleId: "mass-assignment",
          severity: "medium",
          confidence: "medium",
          message:
            `The whole request body is passed to ${label}. Whatever fields the caller adds are written too (${SENSITIVE_HINT}). ` +
            `Pick the fields you accept: \`const { name, email } = req.body\` and write only those, or validate the body with a schema that lists them.`,
          location: toLocation(node, filePath),
          sourceSnippet: snippet(target, parsed.sourceCode),
          sinkSnippet: snippet(node, parsed.sourceCode),
        });
      }
    }
    return findings;
  }
}
