import { SyntaxNode, findNodes } from "../parsers/utils";
import { boundNames } from "./engine";

/**
 * Values read from the database, for the stored-XSS check of the template rule: rows that a visitor saved earlier come back through an ORM
 * (`Post.objects.all()`, `Post.query.filter_by(...)`, `session.query(Post)`, `cursor.fetchall()`, `db.posts.find()`) and are handed to a template that
 * prints them raw (`{{ post.body|safe }}`). The request is not in sight, so data flow cannot see it.
 */
const DATABASE_EXPRESSION = /\.objects\b|(?:^|[\s(=])[A-Z]\w*\.query\b|\bsession\.(?:query|execute|scalars)\(|\.fetch(?:all|one|many)\(|\b(?:db|mongo|database|collection)\w*(?:\.\w+)?\.(?:find|find_one|aggregate)\(|\b[A-Z]\w+\.(?:select|get_or_none|all)\(/;

export function isDatabaseExpression(node: SyntaxNode): boolean {
  return DATABASE_EXPRESSION.test(node.text);
}

/** Names assigned a database expression (or something built from one of those names) in this function. */
export function databaseNames(fn: SyntaxNode): Set<string> {
  const names = new Set<string>();
  const assignments = findNodes(fn, (n) => n.type === "assignment");
  for (let pass = 0; pass < 2; pass++) {
    for (const assignment of assignments) {
      const right = assignment.childForFieldName("right");
      const left = assignment.childForFieldName("left");
      if (!right || !left) continue;
      const rooted = findNodes(right, (n) => n.type === "identifier" && names.has(n.text)).length > 0;
      if (isDatabaseExpression(right) || rooted) for (const name of boundNames(left)) names.add(name);
    }
  }
  return names;
}

/** The database name (or database call) a template value is built from, if it is one. */
export function databaseSource(value: SyntaxNode, names: ReadonlySet<string>): string | undefined {
  if (isDatabaseExpression(value)) return "the database";
  return findNodes(value, (n) => n.type === "identifier" && names.has(n.text))[0]?.text;
}
