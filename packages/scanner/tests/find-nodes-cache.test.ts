import { parseSource } from "../src/parsers/ast-parser";
import { findNodes, walk, SyntaxNode } from "../src/parsers/utils";

const SOURCE = "function a(x) { return b(x) + c(x); }\nconst d = (y) => { call(y); other(y); };\nclass K { m(z) { return z.q(1); } }\n";

function reference(root: SyntaxNode, predicate: (n: SyntaxNode) => boolean): SyntaxNode[] {
  const out: SyntaxNode[] = [];
  walk(root, (n) => {
    if (predicate(n)) out.push(n);
  });
  return out;
}

const isCall = (n: SyntaxNode): boolean => n.type === "call_expression";

describe("findNodes keeps the node list of a tree (speed-up, same answers)", () => {
  it("gives the nodes in the same order as a fresh walk, on every call", () => {
    const { tree } = parseSource(SOURCE, "javascript");
    const expected = reference(tree.rootNode, isCall).map((n) => n.startIndex);
    expect(expected.length).toBe(5); // b(x), c(x), call(y), other(y), z.q(1)
    for (let i = 0; i < 3; i++) expect(findNodes(tree.rootNode, isCall).map((n) => n.startIndex)).toEqual(expected);
  });

  it("a query over part of the tree stays inside that part, before and after the whole-tree one", () => {
    const { tree } = parseSource(SOURCE, "javascript");
    const functions = (): SyntaxNode[] => findNodes(tree.rootNode, (n) => n.type === "function_declaration" || n.type === "arrow_function" || n.type === "method_definition");
    const inside = (fn: SyntaxNode): number[] => findNodes(fn, isCall).map((n) => n.startIndex);
    const before = functions().map(inside); // may run before the tree has a cached list
    findNodes(tree.rootNode, isCall);
    const after = functions().map(inside);
    expect(after).toEqual(before);
    expect(after.map((list) => list.length)).toEqual([2, 2, 1]);
  });

  it("several trees at once (the project keeps other files' trees) do not mix up", () => {
    const trees = ["a(1); b(2);", "c(3);", "d(4); e(5); f(6);", "g(7);", "h(8); i(9);"].map((code) => parseSource(code, "javascript").tree);
    for (let round = 0; round < 2; round++) {
      expect(trees.map((t) => findNodes(t.rootNode, isCall).length)).toEqual([2, 1, 3, 1, 2]);
    }
    expect(findNodes(trees[0]!.rootNode, isCall).map((n) => n.text)).toEqual(["a(1)", "b(2)"]);
  });
});
