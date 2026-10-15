import * as fs from "fs";
import * as path from "path";
import { ParsedFile } from "../parsers/ast-parser";
import { SyntaxNode, findNodes, isFunctionNode, snippet, toLocation } from "../parsers/utils";
import { ProjectContext } from "../taint/project";
import { isTrpcResolver } from "../taint/request-params";
import { Finding } from "../types";
import { Analyzer } from "./base-analyzer";
import { ADMIN_CLIENT, OWNERSHIP_HELPER, PUBLIC_ACTION_NAME, USER_REF_ONCE, checksCaller, dbMutations } from "./server-actions";

/**
 * Who may call this? for the handlers of SvelteKit (`+server.ts`, form `actions`), Remix (`action`), Nuxt / Nitro
 * (`server/api`) and tRPC (`mutation`). Like a Server Action, each is a public endpoint: the browser can call it directly
 * with any arguments, whatever the page shows.
 *
 *  - `broken-access-control`: a handler that changes data and never checks who is calling (a tRPC `publicProcedure`, a
 *    SvelteKit action that never looks at `locals`, a Remix `action` with no session, a Nuxt handler with no session).
 *  - `idor`: a handler that does check the caller, but changes the record whose id the caller sent without comparing it
 *    with the caller's own id.
 *
 * What counts as "checks the caller" is deliberately wide (any of the common session helpers, or a hook / middleware that
 * enforces it for the whole project), because a missed finding is cheaper than a wrong one on code that is fine.
 */

type Framework = "sveltekit" | "remix" | "nuxt" | "trpc";

interface Handler {
  framework: Framework;
  /** What the message calls it: `action "remove"`, `tRPC procedure "post.remove"`. */
  label: string;
  /** Name matched against the "public on purpose" list (login, webhook, contact, ...). */
  nameForPublicCheck: string;
  fn: SyntaxNode;
  /** The caller is already known to be authenticated by how the handler is declared (a `protectedProcedure`). */
  authenticatedByDeclaration: boolean;
}

const SVELTE_FILE = /\+(?:server|page\.server|layout\.server)\.[cm]?[jt]s$/;
const MUTATING_VERBS = new Set(["POST", "PUT", "PATCH", "DELETE"]);

// Evidence in the code that the caller is looked at, on top of the generic helpers in server-actions.ts.
const FRAMEWORK_AUTH_HINT =
  /\blocals\.(?:user|session|auth|userId|getSession|getUser|safeGetSession)\b|\bevent\.locals\.(?:user|session|auth)|\b(?:ctx|context)\.(?:session|user|auth|userId|currentUser)\b|\b(?:requireUserSession|getUserSession|serverSupabaseUser|serverSupabaseSession|getServerSession|requireUserId|requireUser|getUserId|getUser|requireAuth|requireSession|getSession|isAuthenticated|authenticator\.isAuthenticated|getAuth|auth)\s*\(|code:\s*["']UNAUTHORIZED["']|\bevent\.context\.(?:user|auth|session|userId)\b|\bcreateError\(\s*\{[^}]*statusCode:\s*40[13]|\berror\(\s*40[13]\b|\bredirect\(\s*(?:30\d,\s*)?["'`]\/(?:login|signin|sign-in|auth)/i;
// Hooks / middleware that stop the request for the whole project when nobody is signed in.
const ENFORCING_HOOK =
  /(?:locals\.(?:user|session)|getSession|getUser|session|auth)[\s\S]{0,600}?(?:redirect\(\s*(?:30\d,\s*)?["'`]|error\(\s*40[13]|status:\s*40[13]|statusCode:\s*40[13])|(?:redirect\(\s*(?:30\d,\s*)?["'`]|error\(\s*40[13]|status:\s*40[13]|statusCode:\s*40[13])[\s\S]{0,600}?(?:locals\.(?:user|session)|getSession|getUser|session|auth)/i;
const PROTECTED_PROCEDURE = /protected|authed|authenticated|private|admin|staff|member|secure|verified|\bauth\w*Procedure|user\w*Procedure|org\w*Procedure/i;
const ROLE_GATE = /\brole\b\s*(?:===?|!==?|\))|\bisAdmin\b|\brequireAdmin\b|\bhasRole\b|\bhasPermission\b|\bcan\s*\(|\bability\b/i;
const ID_NAME = /^(?:id|.*(?:Id|ID|_id))$/;

function exportedName(fn: SyntaxNode): string | undefined {
  const own = fn.parent?.type === "export_statement" ? fn.childForFieldName("name")?.text : undefined;
  if (own) return own;
  const declarator = fn.parent?.type === "variable_declarator" ? fn.parent : undefined;
  if (declarator?.parent?.parent?.type === "export_statement") return declarator.childForFieldName("name")?.text;
  return undefined;
}

/** Each member function of `export const actions = { create: async (...) => ..., default: ... }`. */
function svelteActions(root: SyntaxNode): { name: string; fn: SyntaxNode }[] {
  const out: { name: string; fn: SyntaxNode }[] = [];
  for (const declarator of findNodes(root, (n) => n.type === "variable_declarator" && n.childForFieldName("name")?.text === "actions")) {
    const object = declarator.childForFieldName("value");
    if (object?.type !== "object") continue;
    for (const member of object.namedChildren) {
      if (member.type === "pair") {
        const value = member.childForFieldName("value");
        if (value && isFunctionNode(value)) out.push({ name: member.childForFieldName("key")?.text ?? "default", fn: value });
      } else if (member.type === "method_definition") {
        out.push({ name: member.childForFieldName("name")?.text ?? "default", fn: member });
      }
    }
  }
  return out;
}

/** The function handed to `defineEventHandler(...)` / `eventHandler(...)` (or its `handler:` member). */
function nitroHandlers(root: SyntaxNode): SyntaxNode[] {
  const out: SyntaxNode[] = [];
  for (const call of findNodes(root, (n) => n.type === "call_expression")) {
    const callee = call.childForFieldName("function")?.text ?? "";
    if (!/^(?:defineEventHandler|eventHandler|defineCachedEventHandler)$/.test(callee)) continue;
    const arg = call.childForFieldName("arguments")?.namedChild(0);
    if (!arg) continue;
    if (isFunctionNode(arg)) out.push(arg);
    else if (arg.type === "object") {
      for (const member of arg.namedChildren) {
        const value = member.type === "pair" && member.childForFieldName("key")?.text === "handler" ? member.childForFieldName("value") : null;
        if (value && isFunctionNode(value)) out.push(value);
      }
    }
  }
  return out;
}

/** `publicProcedure.input(z.object(...)).mutation(fn)` -> `publicProcedure`; with `.use(...)` anywhere in the chain -> undefined (unknown). */
function procedureRoot(resolver: SyntaxNode): { root: string; hasMiddleware: boolean } | undefined {
  const call = resolver.parent?.parent;
  let chain: SyntaxNode | null | undefined = call?.childForFieldName("function")?.childForFieldName("object");
  let hasMiddleware = false;
  while (chain) {
    if (chain.type === "call_expression") {
      const callee = chain.childForFieldName("function");
      if (callee?.type === "member_expression" && callee.childForFieldName("property")?.text === "use") hasMiddleware = true;
      chain = callee?.type === "member_expression" ? callee.childForFieldName("object") : callee;
    } else if (chain.type === "member_expression") {
      const text = chain.text;
      if (/procedure/i.test(chain.childForFieldName("property")?.text ?? "") || /^(?:t|trpc)\./.test(text)) return { root: text, hasMiddleware };
      chain = chain.childForFieldName("object");
    } else if (chain.type === "identifier") {
      return { root: chain.text, hasMiddleware };
    } else {
      return undefined;
    }
  }
  return undefined;
}

function trpcName(resolver: SyntaxNode): string {
  const pair = resolver.parent?.parent?.parent;
  const key = pair?.type === "pair" ? pair.childForFieldName("key")?.text : undefined;
  const router = pair?.parent?.parent?.parent;
  const owner = router?.type === "variable_declarator" ? router.childForFieldName("name")?.text?.replace(/Router$/, "") : undefined;
  return [owner, key].filter(Boolean).join(".") || "procedure";
}

function walkUpFor(start: string, names: string[], read: (text: string) => boolean): boolean {
  let dir = path.dirname(path.resolve(start));
  for (let depth = 0; depth < 8; depth++) {
    for (const name of names) {
      const candidate = path.join(dir, name);
      if (!fs.existsSync(candidate)) continue;
      try {
        if (read(fs.readFileSync(candidate, "utf8"))) return true;
      } catch {
        // an unreadable file: keep looking
      }
    }
    if (fs.existsSync(path.join(dir, "package.json"))) break;
    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return false;
}

function hasEnforcingHook(filePath: string, framework: Framework): boolean {
  if (framework === "sveltekit") {
    return walkUpFor(filePath, ["hooks.server.ts", "hooks.server.js", "src/hooks.server.ts", "src/hooks.server.js"], (t) => ENFORCING_HOOK.test(t));
  }
  if (framework === "nuxt") {
    // server/middleware/*.ts: any file there that stops unauthenticated requests
    let dir = path.dirname(path.resolve(filePath));
    for (let depth = 0; depth < 8; depth++) {
      const middleware = path.join(dir, "server", "middleware");
      if (fs.existsSync(middleware)) {
        try {
          if (fs.readdirSync(middleware).some((f) => /\.[cm]?[jt]s$/.test(f) && ENFORCING_HOOK.test(fs.readFileSync(path.join(middleware, f), "utf8")))) return true;
        } catch {
          // unreadable: not evidence
        }
      }
      if (fs.existsSync(path.join(dir, "package.json"))) break;
      const parent = path.dirname(dir);
      if (parent === dir) break;
      dir = parent;
    }
  }
  return false;
}

function findHandlers(parsed: ParsedFile, filePath: string): Handler[] {
  const root = parsed.tree.rootNode;
  const text = parsed.sourceCode;
  const normalized = filePath.replace(/\\/g, "/");
  const handlers: Handler[] = [];

  if (SVELTE_FILE.test(normalized)) {
    for (const fn of findNodes(root, isFunctionNode)) {
      const name = exportedName(fn);
      if (name && MUTATING_VERBS.has(name)) {
        handlers.push({ framework: "sveltekit", label: `endpoint ${name} of ${path.basename(path.dirname(normalized))}/${path.basename(normalized)}`, nameForPublicCheck: normalized, fn, authenticatedByDeclaration: false });
      }
    }
    for (const action of svelteActions(root)) {
      handlers.push({ framework: "sveltekit", label: `form action "${action.name}"`, nameForPublicCheck: `${normalized} ${action.name}`, fn: action.fn, authenticatedByDeclaration: false });
    }
  }

  if (/\bexport\s+(?:async\s+)?(?:function|const)\s+action\b/.test(text)) {
    for (const fn of findNodes(root, isFunctionNode)) {
      if (exportedName(fn) === "action") handlers.push({ framework: "remix", label: `Remix action of ${path.basename(normalized)}`, nameForPublicCheck: normalized, fn, authenticatedByDeclaration: false });
    }
  }

  if (/(?:^|\/)server\/(?:api|routes)\//.test(normalized) && /defineEventHandler|eventHandler|defineCachedEventHandler/.test(text)) {
    for (const fn of nitroHandlers(root)) {
      handlers.push({ framework: "nuxt", label: `handler ${normalized.slice(normalized.lastIndexOf("/server/") + 1)}`, nameForPublicCheck: normalized, fn, authenticatedByDeclaration: false });
    }
  }

  if (/[pP]rocedure/.test(text) && /\.mutation\(/.test(text)) {
    for (const fn of findNodes(root, (n) => isFunctionNode(n) && isTrpcResolver(n))) {
      const call = fn.parent?.parent;
      if (call?.childForFieldName("function")?.childForFieldName("property")?.text !== "mutation") continue;
      const chain = procedureRoot(fn);
      if (!chain || chain.hasMiddleware) continue; // `.use(isAuthed)` and the like: the middleware may be the check
      const protectedByName = PROTECTED_PROCEDURE.test(chain.root);
      const isPublicRoot = /(?:^|\.)(?:public\w*Procedure|procedure|baseProcedure|anon\w*Procedure|unprotected\w*Procedure|publicProcedure)$/i.test(chain.root) || /^(?:t|trpc)\.procedure$/.test(chain.root);
      if (!protectedByName && !isPublicRoot) continue; // a procedure type we cannot judge by its name
      const name = trpcName(fn);
      handlers.push({ framework: "trpc", label: `tRPC procedure "${name}"`, nameForPublicCheck: name, fn, authenticatedByDeclaration: protectedByName });
    }
  }
  return handlers;
}

/** Names that carry an id sent by the caller: `input.id`, `params.postId`, `form.get("id")`, `getRouterParam(event, "id")`, `const { id } = body`. */
function idInputs(fn: SyntaxNode): string[] {
  const text = fn.text;
  const names = new Set<string>();
  for (const m of text.matchAll(/\b(?:input|body|params|data|form|formData|query|payload|opts\.input)\.(\w+)/g)) if (ID_NAME.test(m[1] ?? "")) names.add(m[1] as string);
  for (const m of text.matchAll(/\.get\(\s*["'`](\w+)["'`]\s*\)/g)) if (ID_NAME.test(m[1] ?? "")) names.add(m[1] as string);
  for (const m of text.matchAll(/getRouterParam\(\s*\w+\s*,\s*["'`](\w+)["'`]/g)) if (ID_NAME.test(m[1] ?? "")) names.add(m[1] as string);
  for (const m of text.matchAll(/\{([^}]*)\}\s*=\s*(?:await\s+)?(?:input|body|params|data|opts\.input|readBody\([^)]*\)|getQuery\([^)]*\))/g)) {
    for (const part of (m[1] ?? "").split(",")) {
      const name = (part.split(":")[0] ?? "").trim();
      if (ID_NAME.test(name)) names.add(name);
    }
  }
  return [...names];
}

function mentionsId(argumentsText: string, id: string): boolean {
  return new RegExp(`\\b(?:input|body|params|data|form|formData|query|payload)\\.${id}\\b|(?<![.\\w])${id}(?![\\w:])|\\.get\\(\\s*["'\`]${id}["'\`]`).test(argumentsText);
}

export class FrameworkAccessAnalyzer implements Analyzer {
  analyze(parsed: ParsedFile, filePath: string, context?: ProjectContext): Finding[] {
    const text = parsed.sourceCode;
    // Cheap exits first: most files are none of these.
    if (!/\+server|\+page\.server|\+layout\.server|\baction\b|server[\\/](?:api|routes)|[pP]rocedure/.test(text + " " + filePath)) return [];
    const handlers = findHandlers(parsed, filePath);
    if (handlers.length === 0) return [];
    const project = context ?? ProjectContext.forSingleFile(filePath, parsed);
    const info = project.fileInfo(filePath, parsed);
    const findings: Finding[] = [];

    for (const handler of handlers) {
      const { fn } = handler;
      if (PUBLIC_ACTION_NAME.test(handler.nameForPublicCheck)) continue;
      const mutations = dbMutations(fn);
      if (mutations.length === 0) continue;
      // A Supabase client built from the caller's cookies acts AS the caller: Row Level Security decides (see the supabase-rls rule).
      const throughRls = mutations.every((m) => /\.from\(/.test(m.childForFieldName("function")?.text ?? "")) && !ADMIN_CLIENT.test(fn.text);
      if (throughRls) continue;

      const callerKnown =
        handler.authenticatedByDeclaration ||
        FRAMEWORK_AUTH_HINT.test(fn.text) ||
        checksCaller(fn, info, project) ||
        hasEnforcingHook(filePath, handler.framework);
      if (!callerKnown) {
        findings.push({
          ruleId: "broken-access-control",
          severity: "high",
          confidence: "medium",
          message:
            `${capitalize(handler.label)} changes data but never checks who is calling it. It is a public endpoint: anyone can call it directly, ` +
            `with any arguments, whether or not the app shows a button for it. ${advice(handler.framework)}`,
          location: toLocation(fn, filePath),
          sourceSnippet: "(no auth check found in the handler)",
          sinkSnippet: snippet(mutations[0] as SyntaxNode, parsed.sourceCode),
        });
        continue;
      }

      // The caller is checked, but is the record they named theirs?
      if (ROLE_GATE.test(fn.text)) continue; // an admin / role gate: not a per-user ownership question
      const ids = idInputs(fn);
      const touched = mutations.filter((m) => ids.some((id) => mentionsId(m.childForFieldName("arguments")?.text ?? "", id)));
      if (touched.length === 0) continue;
      const usesCallerInQuery = findNodes(fn, (n) => n.type === "call_expression").some((c) => USER_REF_ONCE.test(c.childForFieldName("arguments")?.text ?? ""));
      const comparesCaller = findNodes(fn, (n) => n.type === "binary_expression").some(
        (b) => /^(?:===?|!==?)$/.test(b.childForFieldName("operator")?.text ?? "") && USER_REF_ONCE.test(b.text),
      );
      if (usesCallerInQuery || comparesCaller || OWNERSHIP_HELPER.test(fn.text)) continue;
      const target = touched[0] as SyntaxNode;
      findings.push({
        ruleId: "idor",
        severity: "high",
        confidence: "low",
        message:
          `${capitalize(handler.label)} checks that someone is signed in, then changes the record whose id the caller sent (${ids.join(", ")}) without ` +
          `checking that it belongs to the caller. Any signed-in user can pass another user's id. Add the caller's id to the query ` +
          `(\`where: { id, userId: <the caller's id> }\`) or load the record and compare its owner first.`,
        location: toLocation(target, filePath),
        sourceSnippet: `id from the caller: ${ids.join(", ")}`,
        sinkSnippet: snippet(target, parsed.sourceCode),
      });
    }
    return findings;
  }
}

function capitalize(text: string): string {
  return text.charAt(0).toUpperCase() + text.slice(1);
}

function advice(framework: Framework): string {
  switch (framework) {
    case "sveltekit":
      return "Check `locals.user` (set in hooks.server.ts) at the top and return 401 or redirect when it is missing.";
    case "remix":
      return "Read the session at the top of the action (for example `const userId = await requireUserId(request)`) and stop when there is none.";
    case "nuxt":
      return "Read the session at the top of the handler (for example `const { user } = await requireUserSession(event)`) and throw a 401 error when there is none.";
    case "trpc":
      return "Use a `protectedProcedure` that throws `TRPCError({ code: \"UNAUTHORIZED\" })` when `ctx.session` is missing.";
  }
}
