import { ParsedFile } from "../parsers/ast-parser";
import { SyntaxNode, findNodes, snippet, toLocation } from "../parsers/utils";
import { Finding } from "../types";
import { Analyzer } from "./base-analyzer";

/**
 * CORS that lets ANY website read what a logged-in user's browser fetches from this server.
 *
 * Browsers only send cookies (and other credentials) to another origin when the response says
 * `Access-Control-Allow-Credentials: true` AND names that origin. A server that answers "yes" to every origin
 * (`origin: true`, a reflected `Origin` header, `/.*\/`) together with credentials turns every visited website into a
 * client of the user's session: it can call the API as them and read the answers.
 *
 * Quiet on purpose: `origin: "*"` (browsers refuse to combine it with credentials, and without credentials the
 * response carries nothing personal), a list or a single named origin, and any permissive origin WITHOUT credentials.
 */

const REFLECTED_ORIGIN =
  /(?:req|request)\.headers\.origin|(?:req|request)\.headers\[\s*["']origin["']\s*\]|\.get\(\s*["']origin["']\s*\)|\.header\(\s*["']origin["']\s*\)|^origin$/i;
// A callback that tests the origin against something is a (possibly fine) allowlist; one that tests nothing is "allow all".
const ORIGIN_TEST = /\b(?:includes|indexOf|test|match|startsWith|endsWith|has|some|find|every)\s*\(|===|!==|==|!=|\bswitch\b/;

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

function isFunction(node: SyntaxNode): boolean {
  return node.type === "arrow_function" || node.type === "function_expression" || node.type === "function";
}

/** What an `origin` option allows: "all" (every origin is accepted), or undefined (a list, one origin, "*", unknown). */
function permissiveOrigin(value: SyntaxNode): "all" | "reflected" | undefined {
  if (value.type === "true") return "all";
  if (value.type === "regex" && /^\/(?:\.\*|\.\+|\.|\^?\.\*\$?)\/[a-z]*$/.test(value.text)) return "all";
  if (REFLECTED_ORIGIN.test(value.text)) return "reflected";
  if (isFunction(value) && !ORIGIN_TEST.test(value.text) && /\btrue\b|\borigin\b/.test(value.text)) return "all";
  return undefined;
}

export class InsecureCorsAnalyzer implements Analyzer {
  analyze(parsed: ParsedFile, filePath: string): Finding[] {
    const text = parsed.sourceCode;
    if (!/cors|access-control-allow/i.test(text)) return [];
    const root = parsed.tree.rootNode;
    const findings: Finding[] = [];

    const report = (node: SyntaxNode, how: string, confidence: Finding["confidence"], shown: string): void => {
      findings.push({
        ruleId: "insecure-cors",
        severity: "high",
        confidence,
        message:
          `CORS accepts ${how} and also allows credentials. Any website a logged-in user visits can then call this server with the ` +
          `user's cookies and read the responses (their data, their CSRF tokens). Name the origins you trust ` +
          `(origin: ["https://app.example.com"]) instead of accepting every origin, or drop credentials: true.`,
        location: toLocation(node, filePath),
        sourceSnippet: shown,
        sinkSnippet: snippet(node, text),
      });
    };

    // 1. The cors package (Express) and @fastify/cors: cors({ origin, credentials }) / register(cors, { ... })
    for (const call of findNodes(root, (n) => n.type === "call_expression")) {
      const callee = call.childForFieldName("function")?.text ?? "";
      const args = call.childForFieldName("arguments")?.namedChildren ?? [];
      let options: SyntaxNode | undefined;
      if (/(?:^|\.)cors$/i.test(callee)) options = args.find((a) => a.type === "object");
      else if (/\.register$/.test(callee) && /cors/i.test(args[0]?.text ?? "")) options = args.find((a, i) => i > 0 && a.type === "object");
      if (!options) continue;
      const props = propertyMap(options);
      const origin = props.get("origin");
      const credentials = props.get("credentials");
      if (!origin || credentials?.text !== "true") continue;
      const verdict = permissiveOrigin(origin);
      if (verdict) {
        report(call, verdict === "all" ? "every origin" : "whatever origin the request names", verdict === "all" ? "high" : "medium", `origin: ${origin.text.slice(0, 40)}, credentials: true`);
      }
    }

    // 2. Headers written by hand: res.setHeader("Access-Control-Allow-Origin", req.headers.origin) next to ...-Credentials: true
    const grantsCredentials = /access-control-allow-credentials["'`\s,:]+["'`]?true/i.test(text);
    if (grantsCredentials) {
      for (const call of findNodes(root, (n) => n.type === "call_expression")) {
        const callee = call.childForFieldName("function")?.text ?? "";
        if (!/(?:^|\.)(?:setHeader|header|set|append|writeHead)$/.test(callee)) continue;
        const args = call.childForFieldName("arguments")?.namedChildren ?? [];
        if (args[0]?.type === "string" && /^["'`]access-control-allow-origin["'`]$/i.test(args[0].text) && args[1] && REFLECTED_ORIGIN.test(args[1].text)) {
          report(call, "whatever origin the request names", "medium", call.text.slice(0, 60));
        }
      }
      // ...or as an object of headers (Next.js: new Response(body, { headers: { ... } }))
      for (const object of findNodes(root, (n) => n.type === "object")) {
        const props = propertyMap(object);
        const origin = [...props].find(([key]) => /^access-control-allow-origin$/i.test(key))?.[1];
        const credentials = [...props].find(([key]) => /^access-control-allow-credentials$/i.test(key))?.[1];
        if (origin && credentials && /true/.test(credentials.text) && REFLECTED_ORIGIN.test(origin.text)) {
          report(object, "whatever origin the request names", "medium", "Access-Control-Allow-Origin: <request origin>");
        }
      }
    }
    return findings;
  }
}
