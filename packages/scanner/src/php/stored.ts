import { SyntaxNode, findNodes } from "../parsers/utils";

/**
 * Values read from the database, for the stored-XSS check of Blade views: `view("posts", ["posts" => Post::all()])` or
 * `$posts = Post::latest()->get(); return view("posts", compact("posts"));` with `{!! $post->body !!}` in the view. Rows a visitor saved earlier
 * come back through Eloquent, `DB::table()`, PDO or mysqli; the request is not in sight, so data flow cannot see it.
 */
const DATABASE_EXPRESSION = /\b[A-Z]\w*::(?:all|find|findOrFail|where|latest|oldest|orderBy|paginate|get|first|query|with|select)\b|\bDB::(?:table|select)\b|->(?:fetchAll|fetch_all|fetchObject|paginate|findOrFail)\(|\bmysqli_(?:fetch_\w+|query)\(|\$\w*(?:pdo|db|conn)\w*->(?:query|prepare)\(/i;

export function isDatabaseExpression(node: SyntaxNode): boolean {
  return DATABASE_EXPRESSION.test(node.text);
}

/** Variables assigned a database expression (or built from one) in this scope. */
export function databaseNames(scope: SyntaxNode): Set<string> {
  const names = new Set<string>();
  const assignments = findNodes(scope, (n) => n.type === "assignment_expression");
  for (let pass = 0; pass < 2; pass++) {
    for (const assignment of assignments) {
      const left = assignment.childForFieldName("left");
      const right = assignment.childForFieldName("right");
      if (left?.type !== "variable_name" || !right) continue;
      const rooted = findNodes(right, (n) => n.type === "variable_name" && names.has(n.text)).length > 0;
      if (isDatabaseExpression(right) || rooted) names.add(left.text);
    }
  }
  return names;
}

export function databaseSource(value: SyntaxNode | string, names: ReadonlySet<string>): string | undefined {
  if (typeof value === "string") return names.has(value) ? value : undefined;
  if (isDatabaseExpression(value)) return "the database";
  if (value.type === "variable_name" && names.has(value.text)) return value.text;
  return findNodes(value, (n) => n.type === "variable_name" && names.has(n.text))[0]?.text;
}
