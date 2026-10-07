import { ParsedFile } from "../parsers/ast-parser";
import { SyntaxNode, findNodes, snippet, toLocation } from "../parsers/utils";
import { Finding } from "../types";
import { Analyzer, AnalyzerConfig, BaseAnalyzer } from "./base-analyzer";
import { databaseKind } from "./project-info";

// ---------------------------------------------------------------------------
// Part 1: operator injection. `User.findOne({ name: req.body.name })` with a
// JSON body of {"name": {"$ne": null}} matches every user: the attacker
// supplies a query *operator object* where the code expected a string.
// Only sources that can carry objects count: req.body / req.query (Express's
// qs parser turns ?a[$ne]=1 into an object) and Next.js `await request.json()`.
// req.params, req.cookies and searchParams.get() are always strings — not flagged.
// ---------------------------------------------------------------------------
const OBJECT_SOURCE_MEMBER = /^req\.(body|query)(\.\w+|\[[^\]]*\])?$/;
const OBJECT_SOURCE_CALL = /^(req|request)\.json$/;
// MongoDB / Mongoose query methods (Prisma/Sequelize names are intentionally absent:
// their typed APIs make this pattern far noisier).
const MONGO_METHOD =
  /^(find|findOne|findOneAndUpdate|findOneAndDelete|findOneAndReplace|updateOne|updateMany|deleteOne|deleteMany|replaceOne|countDocuments|distinct|aggregate)$/;
// String(x), Number(x), `${x}`, x.toString() force a string, which can't hold an operator object.
const STRINGIFYING_CALLEE = /^(String|Number|parseInt|parseFloat|Boolean|encodeURIComponent)$/;

function isStringified(node: SyntaxNode): boolean {
  const parent = node.parent;
  if (!parent) return false;
  if (parent.type === "template_substitution") return true;
  // { field: { $eq: value } } is the recommended defence: $eq pins the value as a
  // literal to compare against, so an object smuggled in can't act as an operator.
  if (parent.type === "pair" && parent.childForFieldName("key")?.text.replace(/^["'`]|["'`]$/g, "") === "$eq") {
    return true;
  }
  if (parent.type === "arguments") {
    const call = parent.parent;
    const callee = call?.childForFieldName("function");
    return !!callee && callee.type === "identifier" && STRINGIFYING_CALLEE.test(callee.text);
  }
  if (parent.type === "member_expression" && parent.childForFieldName("object")?.id === node.id) {
    return /^(toString|trim|toLowerCase|toUpperCase)$/.test(parent.childForFieldName("property")?.text ?? "");
  }
  return false;
}

/** `req.body` inside `req.body.name` -> the whole `req.body.name` chain (the value that is actually used). */
function outermostChain(node: SyntaxNode): SyntaxNode {
  let current = node;
  for (;;) {
    const parent = current.parent;
    const isLink =
      !!parent &&
      (parent.type === "member_expression" || parent.type === "subscript_expression") &&
      parent.childForFieldName("object")?.id === current.id;
    // Stop at a method call like .toString(): that is handled by isStringified on `current`.
    if (!isLink || !parent || /^(toString|trim|toLowerCase|toUpperCase)$/.test(parent.childForFieldName("property")?.text ?? "")) {
      return current;
    }
    current = parent;
  }
}

function isObjectCapableSource(node: SyntaxNode): boolean {
  if (node.type === "member_expression" || node.type === "subscript_expression") {
    return OBJECT_SOURCE_MEMBER.test(node.text) && !isStringified(outermostChain(node));
  }
  if (node.type === "call_expression") {
    const callee = node.childForFieldName("function");
    return !!callee && callee.type === "member_expression" && OBJECT_SOURCE_CALL.test(callee.text) && !isStringified(node);
  }
  return false;
}

function isMongoQueryCall(node: SyntaxNode): boolean {
  if (node.type !== "call_expression") return false;
  const callee = node.childForFieldName("function");
  if (!callee || callee.type !== "member_expression") return false;
  const property = callee.childForFieldName("property");
  return !!property && MONGO_METHOD.test(property.text);
}

class OperatorInjectionAnalyzer extends BaseAnalyzer {
  protected config(): AnalyzerConfig {
    return {
      ruleId: "nosql-injection",
      severity: "high",
      confidence: "medium",
      isSource: isObjectCapableSource,
      isSink: isMongoQueryCall,
      messageFor: (via) =>
        `Request data ('${via}') goes into a MongoDB query without being forced to a string. A JSON body like ` +
        `{"field": {"$ne": null}} turns it into a query operator and can bypass a login or match every record. ` +
        `Cast with String(...) or validate the type (zod, joi) before querying.`,
    };
  }
}

// ---------------------------------------------------------------------------
// Part 2: `$where`. It runs a JavaScript string inside the database, so any
// dynamic value interpolated into it is code injection — and the input often
// reaches it through another file, which per-function taint tracking can't
// follow. So this part needs no source: a *dynamic* `$where` is the finding.
// ---------------------------------------------------------------------------
const NUMERIC_COERCION = /^(parseInt|parseFloat|Number|BigInt)$/;

function isNumericExpression(expr: SyntaxNode, scope: SyntaxNode): boolean {
  if (expr.type === "number") return true;
  if (expr.type === "unary_expression" && expr.text.startsWith("+")) return true;
  if (expr.type === "call_expression") {
    const callee = expr.childForFieldName("function");
    return !!callee && (NUMERIC_COERCION.test(callee.text) || /^Math\./.test(callee.text));
  }
  if (expr.type === "identifier") {
    // `const n = parseInt(x, 10); ... ${n}` — look for how the variable was initialised.
    const declarations = findNodes(
      scope,
      (n) => n.type === "variable_declarator" && n.childForFieldName("name")?.text === expr.text,
    );
    const init = declarations[0]?.childForFieldName("value");
    return !!init && isNumericExpression(init, scope);
  }
  return false;
}

function enclosingScope(node: SyntaxNode): SyntaxNode {
  let current: SyntaxNode | null = node.parent;
  while (current) {
    if (/function|arrow_function|method_definition|program/.test(current.type)) return current;
    current = current.parent;
  }
  return node;
}

/** The dynamic parts of a `$where` value that aren't provably numeric. */
function untrustedParts(value: SyntaxNode): SyntaxNode[] {
  const scope = enclosingScope(value);
  if (value.type === "string" || value.type === "number") return [];
  if (value.type === "template_string") {
    return findNodes(value, (n) => n.type === "template_substitution")
      .map((sub) => sub.namedChild(0))
      .filter((e): e is SyntaxNode => !!e && !isNumericExpression(e, scope));
  }
  if (value.type === "binary_expression") {
    const parts: SyntaxNode[] = [];
    const walk = (n: SyntaxNode): void => {
      if (n.type === "binary_expression") {
        for (const child of n.namedChildren) walk(child);
      } else if (n.type !== "string" && !isNumericExpression(n, scope)) {
        parts.push(n);
      }
    };
    walk(value);
    return parts;
  }
  if (value.type === "arrow_function" || value.type === "function_expression" || value.type === "function") return [];
  return isNumericExpression(value, scope) ? [] : [value];
}

function isWherePair(node: SyntaxNode): boolean {
  if (node.type !== "pair") return false;
  const key = node.childForFieldName("key")?.text.replace(/^["'`]|["'`]$/g, "");
  return key === "$where";
}

function findWhereFindings(parsed: ParsedFile, filePath: string): Finding[] {
  const findings: Finding[] = [];
  for (const pair of findNodes(parsed.tree.rootNode, isWherePair)) {
    const value = pair.childForFieldName("value");
    if (!value) continue;
    const parts = untrustedParts(value);
    const first = parts[0];
    if (!first) continue;
    findings.push({
      ruleId: "nosql-injection",
      severity: "high",
      confidence: "medium",
      message:
        `A MongoDB $where query is built from a dynamic value ('${snippet(first, parsed.sourceCode)}'). $where runs ` +
        `its string as JavaScript inside the database, so attacker-controlled text in it can run arbitrary code or ` +
        `hang the query (e.g. while(true){}). Avoid $where; use normal query operators, or at least coerce the value ` +
        `to a number with parseInt/Number first.`,
      location: toLocation(pair, filePath),
      sourceSnippet: snippet(first, parsed.sourceCode),
      sinkSnippet: snippet(pair, parsed.sourceCode),
    });
  }
  return findings;
}

/** NoSQL injection: operator objects from the request, and dynamic `$where` strings. */
export class NoSqlInjectionAnalyzer implements Analyzer {
  private readonly operatorInjection = new OperatorInjectionAnalyzer();

  analyze(parsed: ParsedFile, filePath: string): Finding[] {
    // A SQL-only project (Sequelize, Prisma, ...) has no MongoDB operator objects to inject.
    // `$where` is MongoDB syntax by definition, so that part always runs.
    const operatorFindings = databaseKind(filePath) === "sql" ? [] : this.operatorInjection.analyze(parsed, filePath);
    return [...operatorFindings, ...findWhereFindings(parsed, filePath)];
  }
}
