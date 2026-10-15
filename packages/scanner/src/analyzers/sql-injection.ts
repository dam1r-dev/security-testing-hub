import { SyntaxNode } from "../parsers/utils";
import { AnalyzerConfig, BaseAnalyzer, firstArgument } from "./base-analyzer";
import { isRequestSource } from "./sources";

// db.query(...), pool.execute(...), knex.raw(...), sequelize.query(...),
// db.prepare(...) (better-sqlite3, node:sqlite), etc.
const SINK_CALLEE_PATTERN = /(^|\.)(query|execute|raw|prepare)$/;

// Prisma: $queryRawUnsafe / $executeRawUnsafe take the statement as a string. $queryRaw / $executeRaw are safe as a tagged
// template (prisma.$queryRaw`... ${id}`: the values are bound) and unsafe when called with a string built by hand.
const PRISMA_UNSAFE_PATTERN = /(^|\.)\$(queryRawUnsafe|executeRawUnsafe)$/;
const PRISMA_RAW_PATTERN = /(^|\.)\$(queryRaw|executeRaw)$/;

function isSink(node: SyntaxNode): boolean {
  if (node.type !== "call_expression") return false;
  const callee = node.childForFieldName("function");
  if (!callee) return false;
  if (callee.type !== "member_expression" && callee.type !== "identifier") return false;
  if (PRISMA_UNSAFE_PATTERN.test(callee.text)) return true;
  if (PRISMA_RAW_PATTERN.test(callee.text)) return node.childForFieldName("arguments")?.type !== "template_string";
  return SINK_CALLEE_PATTERN.test(callee.text);
}

/**
 * Detects raw, un-parameterized string concatenation/interpolation of
 * request data into SQL query calls (db.query, pool.execute, knex.raw,
 * db.prepare, ...).
 *
 * Only flags string interpolation into the query text — calls that pass the
 * tainted value as a bound parameter (the 2nd+ argument to db.query(sql, [id]))
 * are the safe, parameterized pattern and are intentionally not flagged.
 */
export class SqlInjectionAnalyzer extends BaseAnalyzer {
  protected config(): AnalyzerConfig {
    return {
      ruleId: "sql-injection",
      severity: "critical",
      confidence: "medium",
      isSource: isRequestSource,
      isSink: (node) => isSink(node) && !usesParameterizedArgs(node),
      sinkArgs: firstArgument, // only the query text; later arguments are bound values
      messageFor: (via) =>
        `User-controlled input ('${via}') flows into a SQL query without parameterization. ` +
        `Use parameterized queries (e.g. db.query('... WHERE id = ?', [${via}])) instead of string interpolation.`,
    };
  }
}

/**
 * If the sink call's first argument is a plain/template string that itself does NOT
 * contain the tainted expression (i.e. taint only reaches a later, bound-parameter
 * argument), treat it as the safe parameterized form and skip it.
 */
function usesParameterizedArgs(sinkCall: SyntaxNode): boolean {
  const args = sinkCall.childForFieldName("arguments");
  if (!args || args.namedChildCount < 2) return false;
  const firstArg = args.namedChild(0);
  if (!firstArg) return false;
  // Parameterized calls pass a static SQL string (with `?` placeholders) as arg 0
  // and the tainted values in an array/args afterwards.
  return firstArg.type === "string" && !firstArg.text.includes("${");
}
