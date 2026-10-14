import { ParsedFile } from "../parsers/ast-parser";
import { SyntaxNode, findNodes, snippet, toLocation } from "../parsers/utils";
import { FileInfo, ProjectContext } from "../taint/project";
import { Finding } from "../types";
import { Analyzer } from "./base-analyzer";
import { findNextHandlers, isNextRouteFile, isServerActionFunction, routeSegments, STATE_CHANGING_METHOD_NAMES } from "./nextjs-routes";
import { dependsOnRateLimiter, sourceFacts } from "./project-info";

/**
 * A login (or one-time-code) endpoint that anyone can call as fast as they like. Passwords and 6-digit codes are
 * guessed by machines: without a limit on attempts per account / per address, a 4-digit PIN takes seconds and a weak
 * password minutes.
 *
 * Only reported where the app checks the credential ITSELF (bcrypt/argon2 compare, a code compared with `===`, a
 * TOTP check): hosted sign-in (Auth.js providers, Clerk, Supabase Auth, Firebase Auth) is rate limited by the
 * provider. And only in a project that shows no rate limiting anywhere: no limiter package, no `rateLimit` /
 * `throttle` / 429 handling / failed-attempt counter in any source file. A limit applied by a gateway or a CDN is
 * invisible here: silence the finding with `// security-hub-ignore missing-rate-limit` in that case.
 */

const GUARDED_PATH = /(?:^|\/)(?:log-?in|sign-?in|signin|authenticate|auth|session|sessions|token|otp|2fa|mfa|totp|verify-?(?:code|otp|2fa|pin)|pin|admin-?login)(?:\/|$|\?|["'`])/i;
const GUARDED_PATH_LITERAL = /["'`][^"'`\n]*\/(?:log-?in|sign-?in|signin|authenticate|auth|session|sessions|token|otp|2fa|mfa|totp|verify-?(?:code|otp|2fa|pin)|pin|admin-?login)\b/i;
const GUARDED_NAME = /^(?:log-?in|sign-?in|signin|authenticate|verify-?(?:code|otp|2fa|pin|totp)|check-?(?:code|otp|pin|password))/i;

// The app compares the secret itself.
const CREDENTIAL_CHECK = new RegExp(
  [
    String.raw`\b(?:bcrypt|bcryptjs|argon2|scrypt)\w*\.(?:compare|compareSync|verify)\s*\(`,
    String.raw`\.compare(?:Sync)?\s*\(|\bcompareSync\s*\(`,
    String.raw`\b(?:comparePassword|verifyPassword|checkPassword|validatePassword|isPasswordValid|passwordMatches)\b`,
    String.raw`\b(?:totp|authenticator|speakeasy)\w*\.(?:verify|check|totp\.verify)\s*\(`,
    String.raw`\b(?:otp|code|pin|token)\w*\s*(?:===|!==)\s*\w`,
    String.raw`\bpassword\w*\s*(?:===|!==)\s*\w`,
    String.raw`timingSafeEqual`,
  ].join("|"),
  "i",
);

const ROUTE_METHODS = new Set(["post", "all", "put"]);
const ROUTER_OBJECT = /^(?:app|router)$|router$/i;

function isGuardedPath(text: string): boolean {
  return GUARDED_PATH.test(text);
}

/** Does this code, or a project function it calls (two levels deep), check a credential? */
function checksCredential(node: SyntaxNode, info: FileInfo | undefined, project: ProjectContext, depth: number): boolean {
  if (CREDENTIAL_CHECK.test(node.text)) return true;
  if (!info || depth <= 0) return false;
  for (const call of info.callsIn(node)) {
    const fn = project.resolveCallee(call, info);
    if (fn && checksCredential(fn.node, fn.info, project, depth - 1)) return true;
  }
  return false;
}

function routeRegistrations(root: SyntaxNode): SyntaxNode[] {
  return findNodes(root, (n) => {
    if (n.type !== "call_expression") return false;
    const callee = n.childForFieldName("function");
    if (callee?.type !== "member_expression") return false;
    const object = callee.childForFieldName("object")?.text ?? "";
    const method = callee.childForFieldName("property")?.text.toLowerCase() ?? "";
    return ROUTER_OBJECT.test(object) && ROUTE_METHODS.has(method) && n.childForFieldName("arguments")?.namedChild(0)?.type === "string";
  });
}

/** Handlers passed to a route registration: inline functions and names that resolve to project functions. */
function handlerNodes(route: SyntaxNode, info: FileInfo | undefined, project: ProjectContext): SyntaxNode[] {
  const out: SyntaxNode[] = [];
  const args = route.childForFieldName("arguments");
  for (let i = 1; args && i < args.namedChildCount; i++) {
    const arg = args.namedChild(i);
    if (!arg) continue;
    if (arg.type === "identifier" || arg.type === "member_expression") {
      const entity = info ? project.resolve(arg.type === "identifier" ? info.lookup(arg.text, route) : info.entityFromExpr(arg)) : undefined;
      if (entity?.kind === "fn") out.push(entity.fn.node);
    } else {
      out.push(arg);
    }
  }
  return out;
}

export class MissingRateLimitAnalyzer implements Analyzer {
  analyze(parsed: ParsedFile, filePath: string, context?: ProjectContext): Finding[] {
    const text = parsed.sourceCode;
    // cheap exit: a target is a route whose path is written out in the file (a string such as "/login"), a Next route file,
    // a Server Action or an Auth.js Credentials provider
    if (!isNextRouteFile(filePath) && !GUARDED_PATH_LITERAL.test(text) && !/["']use server["']/.test(text) && !/Credentials/.test(text)) return [];
    const root = parsed.tree.rootNode;
    const project = context ?? ProjectContext.forSingleFile(filePath, parsed);
    const info = project.fileInfo(filePath, parsed);

    const targets: Array<{ node: SyntaxNode; what: string }> = [];

    if (isNextRouteFile(filePath)) {
      const segments = routeSegments(filePath).join("/");
      if (isGuardedPath(`/${segments}/`)) {
        for (const handler of findNextHandlers(root)) {
          if (STATE_CHANGING_METHOD_NAMES.has(handler.method) && checksCredential(handler.node, info, project, 2)) {
            targets.push({ node: handler.node, what: `${handler.method} /${segments}` });
          }
        }
      }
    }

    for (const route of routeRegistrations(root)) {
      const pathText = route.childForFieldName("arguments")?.namedChild(0)?.text ?? "";
      if (!isGuardedPath(pathText)) continue;
      if (handlerNodes(route, info, project).some((h) => checksCredential(h, info, project, 2))) {
        targets.push({ node: route, what: `${route.childForFieldName("function")?.text.split(".").pop()?.toUpperCase()} ${pathText.slice(1, -1)}` });
      }
    }

    // Server Actions named like a login / code check
    if (/["']use server["']/.test(text)) {
      for (const fn of findNodes(root, (n) => n.type === "function_declaration" || n.type === "arrow_function" || n.type === "function_expression")) {
        if (!isServerActionFunction(fn)) continue;
        const name = fn.childForFieldName("name")?.text ?? (fn.parent?.type === "variable_declarator" ? fn.parent.childForFieldName("name")?.text : "") ?? "";
        if (GUARDED_NAME.test(name) && checksCredential(fn, info, project, 2)) targets.push({ node: fn, what: `Server Action ${name}` });
      }
    }

    // Auth.js Credentials provider: its authorize() is the login endpoint
    for (const call of findNodes(root, (n) => n.type === "call_expression")) {
      const callee = call.childForFieldName("function")?.text ?? "";
      if (/^Credentials(?:Provider)?$/.test(callee) && checksCredential(call, info, project, 2)) targets.push({ node: call, what: "Credentials sign-in (authorize)" });
    }

    if (targets.length === 0) return [];
    if (dependsOnRateLimiter(filePath) || sourceFacts(filePath)?.rateLimit) return [];

    // one finding per file: they share a single cause
    const first = targets[0] as { node: SyntaxNode; what: string };
    const scope = targets.length > 1 ? `${targets.length} sign-in / code-check endpoints in this file (first one shown)` : `The sign-in / code-check endpoint ${first.what}`;
    return [
      {
        ruleId: "missing-rate-limit",
        severity: "medium",
        confidence: "medium",
        message:
          `${scope} checks a password or code itself, and nothing in this project limits how many tries a client gets (no rate limiter, no throttle, ` +
          `no failed-attempt counter). A script can try thousands of passwords or every 6-digit code in minutes. Add a limit per account and per IP ` +
          `(express-rate-limit, @upstash/ratelimit, rate-limiter-flexible) and lock or slow down after a few failures. If a gateway or CDN already limits ` +
          `this, add \`// security-hub-ignore missing-rate-limit\` above the endpoint.`,
        location: toLocation(first.node, filePath),
        sourceSnippet: "(no rate limiting found in the project)",
        sinkSnippet: snippet(first.node, text),
      },
    ];
  }
}
