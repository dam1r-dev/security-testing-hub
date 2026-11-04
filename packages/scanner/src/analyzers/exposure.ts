import { ParsedFile } from "../parsers/ast-parser";
import { SyntaxNode, findNodes, snippet, toLocation } from "../parsers/utils";
import { Finding } from "../types";
import { Analyzer } from "./base-analyzer";

/**
 * `debug-endpoint`: a route that hands the inside of the server to whoever asks. The development helper an assistant adds "to see what is
 * going on" and nobody removes:
 *
 *  - the whole environment in a response (`res.json(process.env)`): every key, database password and token the server was started with;
 *  - a route named like a debugging page (`/debug`, `/_debug`, `/heapdump`, `/phpinfo`, `/actuator/env`) with no sign of a login check;
 *  - GraphQL introspection / GraphiQL / Playground switched on without a development-only condition, which hands out the whole schema.
 *
 * Plain patterns, no data flow. The first is certain (high); the other two only say a door is open, so they are reported with low confidence.
 */

const RESPONDER = /^(?:res|response|reply|ctx|context|c|NextResponse|Response)$/;
const SEND_METHOD = /^(?:json|send|end|write|jsonp|render)$/;
const ROUTE_VERB = /^(?:get|all|use|post)$/;
const DEBUG_PATH = /^\/(?:_{0,2}debug\w*|heapdump|phpinfo(?:\.php)?|server-status|server-info|actuator\/(?:env|heapdump|beans|mappings|configprops)|_profiler|__inspect|api\/debug|admin\/debug|debug\/\w+)(?:\/|$)/i;
// anything that looks like the route being protected, or only mounted in development
const GUARD = /auth|admin|protect|login|verify|jwt|passport|session|permission|role|guard|api[_-]?key|authorize|token|NODE_ENV|isDev|isProduction|isLocal/i;
const GRAPHQL_SERVER = /^(?:ApolloServer|createYoga|GraphQLServer|graphqlHTTP|createHandler|buildSchema|mercurius|createSchema)$/;
const GRAPHQL_OPEN = /^(?:introspection|graphiql|playground)$/;

function rootName(node: SyntaxNode | null): string {
  let current = node;
  while (current && (current.type === "call_expression" || current.type === "member_expression" || current.type === "await_expression")) {
    current = current.type === "call_expression" ? current.childForFieldName("function") : (current.childForFieldName("object") ?? current.namedChild(0));
  }
  return current?.text ?? "";
}

function isPartOfLongerMember(node: SyntaxNode): boolean {
  const parent = node.parent;
  if (!parent) return false;
  if (parent.type === "member_expression" || parent.type === "subscript_expression") return parent.childForFieldName("object")?.startIndex === node.startIndex && parent.childForFieldName("object")?.type === node.type;
  return false;
}

/** The route is registered inside `if (process.env.NODE_ENV !== "production") { ... }`, or only when a debug flag says so. */
function guardedByCondition(node: SyntaxNode): boolean {
  for (let p: SyntaxNode | null = node.parent; p; p = p.parent) {
    if (p.type === "if_statement" && GUARD.test(p.childForFieldName("condition")?.text ?? "")) return true;
  }
  return false;
}

function stringValue(node: SyntaxNode | null | undefined): string | undefined {
  if (!node) return undefined;
  if (node.type === "string") return node.text.slice(1, -1);
  if (node.type === "template_string" && !node.text.includes("${")) return node.text.slice(1, -1);
  return undefined;
}

export class DebugEndpointAnalyzer implements Analyzer {
  analyze(parsed: ParsedFile, filePath: string): Finding[] {
    const text = parsed.sourceCode;
    if (!/process\.env|debug|phpinfo|heapdump|actuator|_profiler|introspection|graphiql|playground|server-(?:status|info)/i.test(text)) return [];
    const findings: Finding[] = [];
    const seen = new Set<number>();
    const make = (severity: Finding["severity"], confidence: Finding["confidence"], node: SyntaxNode, message: string): void => {
      if (seen.has(node.startIndex)) return;
      seen.add(node.startIndex);
      findings.push({ ruleId: "debug-endpoint", severity, confidence, message, location: toLocation(node, filePath), sourceSnippet: "(code pattern)", sinkSnippet: snippet(node, text) });
    };

    for (const call of findNodes(parsed.tree.rootNode, (n) => n.type === "call_expression" || n.type === "new_expression")) {
      const callee = call.type === "new_expression" ? call.childForFieldName("constructor") : call.childForFieldName("function");
      const args = call.childForFieldName("arguments")?.namedChildren ?? [];

      // res.json(process.env), res.send(JSON.stringify(process.env)), NextResponse.json({ env: process.env }), new Response(JSON.stringify(process.env))
      const responds =
        call.type === "new_expression"
          ? callee?.text === "Response"
          : callee?.type === "member_expression" && SEND_METHOD.test(callee.childForFieldName("property")?.text ?? "") && RESPONDER.test(rootName(callee.childForFieldName("object")));
      if (responds) {
        const whole = args.flatMap((arg) => findNodes(arg, (n) => n.type === "member_expression" && n.text === "process.env" && !isPartOfLongerMember(n)));
        if (whole.length > 0) {
          make(
            "high",
            "medium",
            call,
            "This response contains the whole environment (process.env): every secret the server was started with (database password, API keys, signing secrets) goes to whoever opens the URL. " +
              "Remove the route. If you need to see one setting while debugging, print that one value in the server log and never in a response.",
          );
          continue;
        }
      }

      // app.get("/debug", (req, res) => res.json(...)) with nothing that looks like a login check
      if (call.type === "call_expression" && callee?.type === "member_expression" && ROUTE_VERB.test(callee.childForFieldName("property")?.text ?? "")) {
        const route = stringValue(args[0]);
        if (route !== undefined && DEBUG_PATH.test(route) && !guardedByCondition(call) && args.length > 1 && /\b(?:res|response|reply|ctx|c)\b[\s\S]*\.(?:json|send|end|render)\(|return\s/.test(call.text) && !GUARD.test(call.text)) {
          make(
            "medium",
            "low",
            call,
            `The route "${route}" looks like a debugging page and nothing in it checks who is asking. Debug routes show configuration, memory or request data that helps an attacker. ` +
              "Delete it, or mount it only when NODE_ENV is not production and put it behind your login.",
          );
        }
        continue;
      }

      // new ApolloServer({ introspection: true }), createYoga({ graphiql: true }), graphqlHTTP({ graphiql: true })
      const name = (call.type === "new_expression" ? callee?.text : callee?.text.split(".").pop()) ?? "";
      if (GRAPHQL_SERVER.test(name) && !/NODE_ENV|isDev|isProduction/.test(call.text)) {
        for (const arg of args) {
          if (arg.type !== "object") continue;
          for (const pair of arg.namedChildren) {
            if (pair.type !== "pair") continue;
            const key = (pair.childForFieldName("key")?.text ?? "").replace(/["'`]/g, "");
            if (GRAPHQL_OPEN.test(key) && pair.childForFieldName("value")?.text === "true") {
              make(
                "low",
                "low",
                pair,
                `${key}: true is set without a condition, so the production server hands out its whole GraphQL schema (every query, mutation and field name) and, with GraphiQL or Playground, a page to try them. ` +
                  "Switch it on only outside production: introspection: process.env.NODE_ENV !== 'production'.",
              );
            }
          }
        }
      }
    }
    return findings;
  }
}
