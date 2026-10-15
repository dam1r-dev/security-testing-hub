import { ParsedFile } from "../parsers/ast-parser";
import { SyntaxNode, findNodes, isFunctionNode, snippet, toLocation } from "../parsers/utils";
import { FileInfo, ProjectContext } from "../taint/project";
import { Finding } from "../types";
import { Analyzer } from "./base-analyzer";
import { AUTH_CHECK_HINT } from "./broken-access-control";
import { isServerActionFunction } from "./nextjs-routes";

/**
 * Next.js Server Actions (`"use server"`) are public POST endpoints: the browser can call any exported action
 * directly, with any arguments, whether or not a page ever shows its button. Nothing outside the action (a hidden
 * button, a page that redirects anonymous visitors, even `middleware.ts` on some setups) decides who may run it.
 *
 *  - `broken-access-control`: an action that changes data and never checks who is calling.
 *  - `idor`: an action that does check the caller, but changes the record whose id the caller sent without
 *    comparing it with the caller's own id.
 *
 * The arguments of an action are also request input for every data-flow rule (see request-params.ts).
 */

// Actions that are meant to run before anyone is signed in, or that only write public submissions.
export const PUBLIC_ACTION_NAME = /login|log_?in|sign_?in|sign_?up|register|logout|sign_?out|forgot|reset|verify|confirm|contact|subscribe|newsletter|waitlist|feedback|webhook|analytics|track|callback|oauth|invite|otp/i;

const MUTATION_CALLEE =
  /(?:^|\.)(?:create|createMany|update|updateMany|upsert|delete|deleteMany|insert|insertMany|remove|destroy|findOneAndUpdate|findByIdAndUpdate|findByIdAndDelete|findOneAndDelete|updateOne|deleteOne|insertOne|replaceOne|bulkWrite|setDoc|updateDoc|deleteDoc|addDoc|execute|run|\$executeRaw|\$executeRawUnsafe)$/;
export const DB_OBJECT = /prisma|\bdb\b|database|supabase|drizzle|knex|\bsql\b|collection|model|repo|repository|firestore|admin|\btrx?\b|\borm\b|conn|\bclient\b|\.from\(/i;

const AUTH_CALL =
  /(?:^|\.)(?:auth|getSession|getServerSession|getUser|getCurrentUser|currentUser|requireUser|requireAuth|requireAdmin|requireSession|verifySession|validateRequest|getToken|checkAuth|ensureAuth\w*|authenticate|isAuthenticated|assertAuth\w*|withAuth|protect|guard|verifyIdToken|getAuth)$/i;
export const ADMIN_CLIENT = /service_?role|createAdminClient|supabaseAdmin|getAdminClient|\badmin\.from\(/i;
const SESSION_COOKIE =/cookies\(\)\s*\.get\(\s*["'`][\w-]*(?:session|token|auth)/i;

// A reference to the caller's own id: `userId`, `session.user.id`, `ownerId`, ...
export const USER_REF_ONCE = /\b(?:user|session|currentUser|auth|me|account)\??\.(?:user\??\.)?(?:id|uid|userId)\b|\buserId\b|\buser_id\b|\bownerId\b|\bowner_id\b|\bcreatedBy\b|\bauthorId\b|\buid\b/;

// A helper whose name says it checks ownership (`verifyUserAccess(id)`, `isOwner(...)`).
export const OWNERSHIP_HELPER =
  /\b\w*(?:verify|check|assert|ensure|require|authori[sz]e|validate)\w*(?:Access|Owner|Ownership|Permission|Permissions|Allowed|Authori[sz]ation)\w*\b|\b(?:isOwner|belongsTo|userOwns|ownsResource)\s*\(/i;

const ID_NAME = /^(?:id|.*(?:Id|ID|_id))$/;

function actionName(fn: SyntaxNode): string {
  const own = fn.childForFieldName("name")?.text;
  if (own) return own;
  const declarator = fn.parent?.type === "variable_declarator" ? fn.parent : undefined;
  return declarator?.childForFieldName("name")?.text ?? "default";
}

export function dbMutations(fn: SyntaxNode): SyntaxNode[] {
  return findNodes(fn, (n) => {
    if (n.type !== "call_expression") return false;
    const callee = n.childForFieldName("function")?.text ?? "";
    return MUTATION_CALLEE.test(callee) && DB_OBJECT.test(callee);
  });
}

/** Does this code, or a project function it calls (two levels deep), match `hint`? */
function matches(node: SyntaxNode, hint: RegExp, info: FileInfo | undefined, project: ProjectContext, depth: number): boolean {
  if (hint.test(node.text)) return true;
  if (!info || depth <= 0) return false;
  for (const call of info.callsIn(node)) {
    const fn = project.resolveCallee(call, info);
    if (fn && matches(fn.node, hint, fn.info, project, depth - 1)) return true;
  }
  return false;
}

export function checksCaller(fn: SyntaxNode, info: FileInfo | undefined, project: ProjectContext): boolean {
  if (SESSION_COOKIE.test(fn.text)) return true;
  const calls = findNodes(fn, (n) => n.type === "call_expression");
  if (calls.some((c) => AUTH_CALL.test(c.childForFieldName("function")?.text ?? ""))) return true;
  return matches(fn, AUTH_CHECK_HINT, info, project, 2);
}

/** Names that carry an id sent by the browser: id-like parameters and `formData.get("xId")` keys. */
function idInputs(fn: SyntaxNode): string[] {
  const names = new Set<string>();
  const params = fn.childForFieldName("parameters");
  const pattern = (p: SyntaxNode): SyntaxNode => p.childForFieldName("pattern") ?? p;
  for (const param of params?.namedChildren ?? []) {
    const p = pattern(param);
    const bound = p.type === "identifier" ? [p.text] : findNodes(p, (n) => n.type === "shorthand_property_identifier_pattern" || n.type === "identifier").map((n) => n.text);
    for (const name of bound) if (ID_NAME.test(name)) names.add(name);
  }
  for (const call of findNodes(fn, (n) => n.type === "call_expression")) {
    const callee = call.childForFieldName("function")?.text ?? "";
    if (!/\.get$/.test(callee)) continue;
    const key = call.childForFieldName("arguments")?.namedChild(0);
    if (key?.type === "string") {
      const value = key.text.slice(1, -1);
      if (ID_NAME.test(value)) names.add(value);
    }
  }
  return [...names];
}

export class ServerActionAnalyzer implements Analyzer {
  analyze(parsed: ParsedFile, filePath: string, context?: ProjectContext): Finding[] {
    if (!/["']use server["']/.test(parsed.sourceCode)) return [];
    const project = context ?? ProjectContext.forSingleFile(filePath, parsed);
    const info = project.fileInfo(filePath, parsed);
    const findings: Finding[] = [];

    for (const fn of findNodes(parsed.tree.rootNode, isFunctionNode)) {
      if (!isServerActionFunction(fn)) continue;
      const name = actionName(fn);
      if (PUBLIC_ACTION_NAME.test(name)) continue;
      const mutations = dbMutations(fn);
      if (mutations.length === 0) continue;
      // A Supabase client built from the request's cookies acts AS the caller: Row Level Security decides what the
      // change may touch, and the supabase-rls rule checks the policies. Only a service-role / admin client bypasses it.
      const throughRls = mutations.every((m) => /\.from\(/.test(m.childForFieldName("function")?.text ?? "")) && !ADMIN_CLIENT.test(fn.text);
      if (throughRls) continue;

      if (!checksCaller(fn, info, project)) {
        findings.push({
          ruleId: "broken-access-control",
          severity: "high",
          confidence: "medium",
          message:
            `Server Action \`${name}\` changes data but never checks who is calling it. A Server Action is a public POST endpoint: anyone can ` +
            `call it directly, with any arguments, whether or not a button for it is shown. Check the session at the top of the action ` +
            `(for example \`const user = await getUser(); if (!user) throw new Error("Unauthorized")\`) and the caller's permission for what it changes.`,
          location: toLocation(fn, filePath),
          sourceSnippet: "(no auth check found in the action)",
          sinkSnippet: snippet(mutations[0] as SyntaxNode, parsed.sourceCode),
        });
        continue;
      }

      // The caller is checked, but is the record they named theirs?
      const ids = idInputs(fn);
      const touchesId = mutations.some((m) => ids.some((id) => new RegExp(`\\b${id}\\b|["'\`]${id}["'\`]`).test(m.childForFieldName("arguments")?.text ?? "")) );
      if (!touchesId) continue;
      // Ownership is checked when the caller's id goes into a database call (a filter such as `where: { id, userId }`)
      // or is compared with something (`todo.ownerId !== session.user.id`), or a helper named for it is called.
      // Reading the caller (`const { userId } = await auth()`, `if (!userId)`) is not a check of this record.
      const usesCallerInQuery = findNodes(fn, (n) => n.type === "call_expression").some(
        (c) => DB_OBJECT.test(c.childForFieldName("function")?.text ?? "") && USER_REF_ONCE.test(c.childForFieldName("arguments")?.text ?? ""),
      );
      const comparesCaller = findNodes(fn, (n) => n.type === "binary_expression").some(
        (b) => /^(?:===?|!==?)$/.test(b.childForFieldName("operator")?.text ?? "") && USER_REF_ONCE.test(b.text),
      );
      if (usesCallerInQuery || comparesCaller || OWNERSHIP_HELPER.test(fn.text)) continue;
      const target = mutations.find((m) => ids.some((id) => (m.childForFieldName("arguments")?.text ?? "").includes(id))) ?? (mutations[0] as SyntaxNode);
      findings.push({
        ruleId: "idor",
        severity: "high",
        confidence: "low",
        message:
          `Server Action \`${name}\` checks that someone is signed in, then changes the record whose id the browser sent (${ids.join(", ")}) without ` +
          `checking that it belongs to the caller. Any signed-in user can pass another user's id. Add the caller's id to the query ` +
          `(\`where: { id, userId: user.id }\`) or load the record and compare its owner first.`,
        location: toLocation(target, filePath),
        sourceSnippet: `id from the browser: ${ids.join(", ")}`,
        sinkSnippet: snippet(target, parsed.sourceCode),
      });
    }
    return findings;
  }
}
