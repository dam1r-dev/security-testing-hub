import { SyntaxNode } from "../parsers/utils";

/** Positional arguments of a call / `new`; stops at the first spread, after which positions are unknown. */
export function callArguments(call: SyntaxNode): SyntaxNode[] {
  const args = call.childForFieldName("arguments");
  if (!args) return [];
  const result: SyntaxNode[] = [];
  for (const arg of args.namedChildren) {
    if (arg.type === "comment") continue;
    if (arg.type === "spread_element") break;
    result.push(arg);
  }
  return result;
}
