import { ParsedFile } from "../parsers/ast-parser";
import { SyntaxNode, enclosingFunction, findNodes, snippet, toLocation } from "../parsers/utils";
import { FileInfo, ProjectContext } from "../taint/project";
import { callTaintFor, sourceReturningCalls } from "../taint/returns";
import { assignmentLike, expressionCarries, getAliases, usesNamesDirectly } from "../taint/simple-taint";
import { Finding, Severity } from "../types";
import { Analyzer } from "./base-analyzer";
import { isRequestSource } from "./sources";

/**
 * JSON Web Tokens used in ways that make them forgeable or immortal:
 *
 *  - `algorithms: ["none"]` / `algorithm: "none"`: tokens with no signature are accepted (or issued)
 *  - `ignoreExpiration: true`: a token stays valid forever, however old
 *  - `jwt.decode(token)` used as if it verified: `decode` only reads the payload; anyone can write one
 *  - `jwt.sign({ id }, secret)` with no expiry: a stolen token works until the secret is changed
 *
 * Covers `jsonwebtoken` (by its usual aliases and named imports) and `jose`'s `SignJWT`.
 */

const LIB = /["'](?:jsonwebtoken|jws)["']/;
const USE_CLIENT = /^(?:\s*(?:\/\/[^\n]*\n|\/\*[\s\S]*?\*\/))*\s*["']use client["']/;

function propertyMap(object: SyntaxNode): Map<string, SyntaxNode> {
  const map = new Map<string, SyntaxNode>();
  for (const child of object.namedChildren) {
    if (child.type === "pair") {
      const key = child.childForFieldName("key")?.text.replace(/^["'`]|["'`]$/g, "");
      const value = child.childForFieldName("value");
      if (key && value) map.set(key, value);
    } else if (child.type === "shorthand_property_identifier") {
      map.set(child.text, child);
    }
  }
  return map;
}

/** Local names the library is known by: `import jwt from "jsonwebtoken"`, `const jwt = require("jsonwebtoken")`, `{ sign, verify }`. */
function libraryNames(text: string): { objects: Set<string>; functions: Map<string, "sign" | "verify" | "decode"> } {
  const objects = new Set<string>(["jwt", "jsonwebtoken"]);
  const functions = new Map<string, "sign" | "verify" | "decode">();
  for (const m of text.matchAll(/import\s+(?:\*\s+as\s+)?(\w+)\s+from\s+["']jsonwebtoken["']/g)) objects.add(m[1] as string);
  for (const m of text.matchAll(/(?:const|let|var)\s+(\w+)\s*=\s*require\(\s*["']jsonwebtoken["']\s*\)/g)) objects.add(m[1] as string);
  const named = (list: string): void => {
    for (const item of list.split(",")) {
      const [original, alias] = item.trim().split(/\s+as\s+|\s*:\s*/);
      if (original === "sign" || original === "verify" || original === "decode") functions.set((alias ?? original).trim(), original);
    }
  };
  for (const m of text.matchAll(/import\s*\{([^}]*)\}\s*from\s*["']jsonwebtoken["']/g)) named(m[1] as string);
  for (const m of text.matchAll(/(?:const|let|var)\s*\{([^}]*)\}\s*=\s*require\(\s*["']jsonwebtoken["']\s*\)/g)) named(m[1] as string);
  return { objects, functions };
}

// A parameter named like a token is almost always the one the caller took from the request.
const TOKEN_PARAM = /token|jwt|bearer|authori[sz]ation|header|cookie/i;

/**
 * Is the value being decoded something the client sent? `decode(security.tokenOf(user))` reads a token the SERVER holds
 * (nothing to forge); `decode(req.headers.authorization)` or `decode(token)` inside `verify(token)` reads one the
 * client wrote.
 */
function cameFromTheRequest(arg: SyntaxNode, root: SyntaxNode, info: FileInfo | undefined): boolean {
  const scope = enclosingFunction(arg) ?? root;
  const sources = findNodes(scope, isRequestSource);
  if (info) sources.push(...sourceReturningCalls(scope, info));
  const callTaint = info ? callTaintFor(info) : undefined;
  const assignments = assignmentLike(scope);
  for (const source of sources) {
    const names = getAliases(source, scope, assignments, callTaint);
    if (expressionCarries(arg, { source, names }, callTaint)) return true;
  }
  // a parameter such as `token` / `authorization`: the caller supplies it
  const fn = enclosingFunction(arg);
  if (fn && info) {
    const tokenParams = new Set(info.functionInfo(fn).params.flat().filter((name) => TOKEN_PARAM.test(name)));
    if (usesNamesDirectly(arg, tokenParams)) return true;
  }
  return false;
}

export class InsecureJwtAnalyzer implements Analyzer {
  analyze(parsed: ParsedFile, filePath: string, context?: ProjectContext): Finding[] {
    const text = parsed.sourceCode;
    const usesJsonwebtoken = LIB.test(text);
    const usesJose = /SignJWT/.test(text) && /["']jose["']/.test(text);
    if ((!usesJsonwebtoken && !usesJose) || USE_CLIENT.test(text)) return [];
    const root = parsed.tree.rootNode;
    const findings: Finding[] = [];
    const project = context ?? ProjectContext.forSingleFile(filePath, parsed);
    const info = project.fileInfo(filePath, parsed);
    const add = (node: SyntaxNode, severity: Severity, confidence: Finding["confidence"], message: string, source: string): void => {
      findings.push({ ruleId: "insecure-jwt", severity, confidence, message, location: toLocation(node, filePath), sourceSnippet: source, sinkSnippet: snippet(node, text) });
    };

    if (usesJsonwebtoken) {
      const { objects, functions } = libraryNames(text);
      const verifiesAnywhere = findNodes(root, (n) => n.type === "call_expression").some((call) => {
        const callee = call.childForFieldName("function")?.text ?? "";
        return functions.get(callee) === "verify" || [...objects].some((o) => callee === `${o}.verify`);
      });

      for (const call of findNodes(root, (n) => n.type === "call_expression")) {
        const callee = call.childForFieldName("function")?.text ?? "";
        let method: "sign" | "verify" | "decode" | undefined = functions.get(callee);
        for (const o of objects) {
          if (callee.startsWith(`${o}.`)) {
            const name = callee.slice(o.length + 1);
            if (name === "sign" || name === "verify" || name === "decode") method = name;
          }
        }
        if (!method) continue;
        const args = call.childForFieldName("arguments")?.namedChildren.filter((a) => a.type !== "comment") ?? [];

        if (method === "verify") {
          const options = args[2]?.type === "object" ? propertyMap(args[2]) : undefined;
          const algorithms = options?.get("algorithms");
          if (algorithms && /["'`]none["'`]/i.test(algorithms.text)) {
            add(call, "critical", "high", `This verifies tokens with algorithms: ${algorithms.text}. The "none" algorithm means a token with no signature at all is accepted, so anyone can write a token for any user. Allow only the algorithm you sign with: { algorithms: ["HS256"] }.`, "algorithms includes none");
          }
          if (options?.get("ignoreExpiration")?.text === "true") {
            add(call, "high", "high", "ignoreExpiration: true makes every token valid forever: a token that leaked once (a log, a browser extension, an old device) can be used for ever. Remove the option so expired tokens are rejected.", "ignoreExpiration: true");
          }
        } else if (method === "sign") {
          const options = args[2]?.type === "object" ? propertyMap(args[2]) : undefined;
          if (/["'`]none["'`]/i.test(options?.get("algorithm")?.text ?? "")) {
            add(call, "critical", "high", 'This issues tokens with algorithm "none": they carry no signature, so nothing stops anyone from editing them. Sign with HS256 (a long secret) or RS256.', 'algorithm: "none"');
            continue;
          }
          // No expiry: only decidable when the payload is written out here and the options (if any) are too.
          const payload = args[0];
          if (payload?.type !== "object" || (args[2] && args[2].type !== "object")) continue;
          const payloadKeys = propertyMap(payload);
          const spread = payload.namedChildren.some((c) => c.type === "spread_element");
          const hasExpiry = payloadKeys.has("exp") || !!options?.has("expiresIn") || !!options?.has("noTimestamp");
          if (!hasExpiry && !spread && args.length >= 2) {
            add(call, "medium", "medium", 'This token never expires: nothing in the payload (exp) or the options (expiresIn) limits its life, so a stolen token works until you change the signing secret. Add an expiry: jwt.sign(payload, secret, { expiresIn: "1h" }).', "no expiresIn / exp");
          }
        } else if (method === "decode" && !verifiesAnywhere && args[0] && cameFromTheRequest(args[0], root, info)) {
          add(call, "high", "medium", "jwt.decode() only reads the payload: it does NOT check the signature, so anyone can hand over a token they wrote themselves with any user id or role. This file never calls jwt.verify(). Use jwt.verify(token, secret) and trust only what it returns.", "decode without verify");
        }
      }
    }

    if (usesJose) {
      // new SignJWT(payload).setProtectedHeader(...).sign(key): no .setExpirationTime(...) anywhere in the chain
      for (const call of findNodes(root, (n) => n.type === "call_expression")) {
        const callee = call.childForFieldName("function");
        if (callee?.type !== "member_expression" || callee.childForFieldName("property")?.text !== "sign") continue;
        const chain = callee.text;
        if (/\bnew\s+SignJWT\b/.test(chain) && !/setExpirationTime|\bexp\b/.test(chain)) {
          add(call, "medium", "medium", "This token never expires: the SignJWT chain has no .setExpirationTime(...), so a stolen token works until the key is rotated. Add .setExpirationTime(\"1h\").", "no setExpirationTime");
        }
      }
    }
    return findings;
  }
}
