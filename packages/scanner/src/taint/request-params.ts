import { isServerActionFunction } from "../analyzers/nextjs-routes";
import { SyntaxNode, isFunctionNode } from "../parsers/utils";
import { boundNames } from "./simple-taint";

/**
 * User input that arrives as a handler's PARAMETERS rather than as `req.body` in the code:
 *
 *   async function upload({ file, body }: Request, res: Response) { ... }   // Express, destructured
 *   export async function GET(request: Request, { params }: Ctx) { ... }     // Next.js route params
 *   export async function loader({ request, params }: LoaderFunctionArgs)   // Remix
 *
 * The names those patterns bind carry request data from the first line of the function, so they
 * seed the taint tracking just like a `req.body` expression would.
 */

export interface Origin {
  /** The parameter pattern (used as the "source" in a finding). */
  node: SyntaxNode;
  /** Local names bound to request data. */
  names: string[];
}

export const REQUEST_KEYS = ["body", "query", "params", "cookies", "headers", "file", "files", "input"] as const;

const REQUEST_TYPE = /Request|Req\b|LoaderFunctionArgs|ActionFunctionArgs|Context\b|Args\b/;
const RESPONSE_NAME = /^_?(res|response|reply)$/;

interface ParamInfo {
  pattern: SyntaxNode | null;
  type: string;
}

function describeParam(param: SyntaxNode): ParamInfo {
  if (param.type === "required_parameter" || param.type === "optional_parameter") {
    return { pattern: param.childForFieldName("pattern"), type: param.childForFieldName("type")?.text ?? "" };
  }
  return { pattern: param, type: "" };
}

/** key -> names bound under that key, for an object pattern like `{ body, params: p, query = {} }`. */
function bindingsByKey(pattern: SyntaxNode): Map<string, string[]> {
  const result = new Map<string, string[]>();
  for (const child of pattern.namedChildren) {
    if (child.type === "shorthand_property_identifier_pattern") {
      result.set(child.text, [child.text]);
    } else if (child.type === "object_assignment_pattern") {
      const left = child.childForFieldName("left");
      if (left) result.set(left.text, [left.text]);
    } else if (child.type === "pair_pattern") {
      const key = child.childForFieldName("key")?.text.replace(/^["'`]|["'`]$/g, "");
      const value = child.childForFieldName("value");
      if (key && value) result.set(key, boundNames(value));
    }
  }
  return result;
}

const ENTRY_POINT_NAMES = new Set(["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD", "load", "loader", "action", "clientLoader", "clientAction"]);

/**
 * An exported `GET` / `load` / `loader` / `action` function, or a member of an `actions = { ... }` object: what SvelteKit and Remix call
 * with the request. Its first parameter is the request context even when it destructures only `{ params }`.
 */
function isFrameworkEntryPoint(fn: SyntaxNode): boolean {
  const declarator = fn.parent?.type === "variable_declarator" ? fn.parent : undefined;
  const name = fn.childForFieldName("name")?.text ?? declarator?.childForFieldName("name")?.text;
  const exported = fn.parent?.type === "export_statement" || declarator?.parent?.parent?.type === "export_statement";
  if (name && ENTRY_POINT_NAMES.has(name) && exported) return true;
  // `export const actions = { default: async ({ request }) => ..., create: ... }`
  const pair = fn.parent;
  if (pair?.type === "pair" || pair?.type === "method_definition") {
    const object = pair.parent;
    const owner = object?.parent;
    return owner?.type === "variable_declarator" && owner.childForFieldName("name")?.text === "actions";
  }
  return false;
}

const TRPC_RESOLVER_METHODS = new Set(["query", "mutation", "subscription"]);

/** The function is the resolver of a tRPC procedure: an argument of `.query(...)`, `.mutation(...)` or `.subscription(...)`. */
export function isTrpcResolver(fn: SyntaxNode): boolean {
  const args = fn.parent;
  if (args?.type !== "arguments") return false;
  const call = args.parent;
  const callee = call?.type === "call_expression" ? call.childForFieldName("function") : null;
  if (callee?.type !== "member_expression") return false;
  const method = callee.childForFieldName("property")?.text ?? "";
  // `.query(` / `.mutation(` are also methods of database clients and query libraries: a tRPC procedure is recognised by its chain
  // (`publicProcedure.input(...).mutation(...)`, `t.procedure.query(...)`), whose root has "procedure" in its name.
  return TRPC_RESOLVER_METHODS.has(method) && /[pP]rocedure/.test(callee.childForFieldName("object")?.text ?? "");
}

export function requestParamOrigins(fn: SyntaxNode, keys: readonly string[] = REQUEST_KEYS): Origin[] {
  if (!isFunctionNode(fn)) return [];
  const params = fn.childForFieldName("parameters")?.namedChildren.filter((p) => p.type !== "comment") ?? [];
  const first = params[0] ? describeParam(params[0]) : undefined;
  const second = params[1] ? describeParam(params[1]) : undefined;
  const origins: Origin[] = [];

  const pick = (pattern: SyntaxNode, wanted: readonly string[]): string[] => {
    const bindings = bindingsByKey(pattern);
    return wanted.flatMap((key) => bindings.get(key) ?? []);
  };

  if (first?.pattern?.type === "object_pattern") {
    const secondIsResponse =
      !!second && ((second.pattern?.type === "identifier" && RESPONSE_NAME.test(second.pattern.text)) || /Response|Reply/.test(second.type));
    const bindings = bindingsByKey(first.pattern);
    // Remix-style `{ request, params }` (no `res` at all) is recognised by its keys.
    const remixStyle = bindings.has("request") && bindings.has("params");
    if (REQUEST_TYPE.test(first.type) || secondIsResponse || remixStyle) {
      const names = pick(first.pattern, keys);
      if (names.length > 0) origins.push({ node: first.pattern, names });
    }
  }

  // Server Actions: every argument comes from the browser (the form data, an id, `prevState`).
  if (isServerActionFunction(fn)) {
    for (const param of params) {
      const pattern = describeParam(param).pattern;
      const names = pattern ? boundNames(pattern) : [];
      if (pattern && names.length > 0) origins.push({ node: pattern, names });
    }
  }

  // SvelteKit: `GET({ params, url, request, locals })` / `load({ params })` / `actions = { default: ({ request, params }) => ... }`.
  // A first parameter that holds `params` next to other members of the RequestEvent is that event: its `params` are the URL's.
  if (first?.pattern?.type === "object_pattern" && keys.includes("params")) {
    const bindings = bindingsByKey(first.pattern);
    const isEvent = ["url", "locals", "cookies", "setHeaders", "platform", "fetch"].some((key) => bindings.has(key)) || isFrameworkEntryPoint(fn);
    if (isEvent && !origins.some((o) => o.node === first.pattern)) {
      const names = pick(first.pattern, ["params"]);
      if (names.length > 0) origins.push({ node: first.pattern, names });
    }
  }

  // tRPC: `.mutation(({ input, ctx }) => ...)` / `.query(async ({ input }) => ...)`: the validated input is still the caller's.
  if (keys.includes("input") && isTrpcResolver(fn) && first?.pattern?.type === "object_pattern") {
    const names = pick(first.pattern, ["input"]);
    if (names.length > 0) origins.push({ node: first.pattern, names });
  }

  // Next.js route handlers: GET(request, { params }) — the dynamic URL segments.
  if (second?.pattern?.type === "object_pattern" && keys.includes("params")) {
    const names = pick(second.pattern, ["params"]);
    if (names.length > 0) origins.push({ node: second.pattern, names });
  }
  return origins;
}
