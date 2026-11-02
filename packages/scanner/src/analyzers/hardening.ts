import { ParsedFile } from "../parsers/ast-parser";
import { SyntaxNode, findNodes, snippet, toLocation } from "../parsers/utils";
import { ProjectContext } from "../taint/project";
import { Finding, Severity, VulnerabilityType } from "../types";
import { Analyzer, AnalyzerConfig, BaseAnalyzer, firstArgument } from "./base-analyzer";
import { isRequestSource } from "./sources";

/**
 * The mistakes an AI assistant makes most often with the standard library, none of which needs data flow to see:
 *
 *  - `weak-crypto`: a password hashed with MD5 / SHA-1, a token or reset code built from `Math.random()`, bcrypt with a cost below 10,
 *    a cipher in ECB mode (or `createCipher`, which has no IV);
 *  - `insecure-cookie`: a session or login cookie that scripts can read (`httpOnly: false`, or left out) or that travels over plain HTTP
 *    (`secure: false`);
 *  - `tls-verification`: `rejectUnauthorized: false`, `NODE_TLS_REJECT_UNAUTHORIZED = "0"`: HTTPS that accepts anyone's certificate.
 *
 * `regex-injection` (a pattern built from the request) is the taint-based one at the end of the file.
 */

/** A name that says the value is a credential, a one-time code or an identifier an attacker must not guess. */
export const SECURITY_NAME = /token|secret|otp|nonce|reset|verif|session|csrf|xsrf|passcode|password|passwd|api[_-]?key|invite|salt|signature|auth[_-]?code/i;
// ...unless the name says the random value is for something else
const NOT_SECURITY = /color|colour|delay|jitter|backoff|animation|retry|shuffle|sample|position|offset|index|angle|speed|size|pick|greeting|message|emoji|avatar|placeholder|demo|mock|fake|test/i;
const PASSWORD_NAME = /pass(?:word|wd|phrase)?\b|pwd/i;
// A cookie that carries the login. Others (theme, language, consent) are meant for scripts.
const AUTH_COOKIE = /token|session|sid\b|auth|jwt|access|refresh|login|remember/i;

type Make = (rule: VulnerabilityType, severity: Severity, node: SyntaxNode, message: string) => void;

function stringValue(node: SyntaxNode | null | undefined): string | undefined {
  if (!node) return undefined;
  if (node.type === "string") return node.text.slice(1, -1);
  if (node.type === "template_string" && !node.text.includes("${")) return node.text.slice(1, -1);
  return undefined;
}

function pairKey(pair: SyntaxNode): string {
  const key = pair.childForFieldName("key");
  return key ? key.text.replace(/^["'`]|["'`]$/g, "") : "";
}

function pairsOf(object: SyntaxNode | null | undefined): SyntaxNode[] {
  return object?.type === "object" ? object.namedChildren.filter((c) => c.type === "pair") : [];
}

function enclosingName(node: SyntaxNode): string {
  for (let p: SyntaxNode | null = node.parent; p; p = p.parent) {
    switch (p.type) {
      case "variable_declarator":
        return p.childForFieldName("name")?.text ?? "";
      case "assignment_expression":
        return p.childForFieldName("left")?.text ?? "";
      case "pair":
        return pairKey(p);
      case "function_declaration":
      case "method_definition":
      case "generator_function_declaration":
        return p.childForFieldName("name")?.text ?? "";
      case "arrow_function":
      case "function_expression":
      case "function":
        // `const makeToken = () => ...`: the arrow has no name of its own, the declarator above it does
        break;
      default:
        break;
    }
  }
  return "";
}

function enclosingFunctionName(node: SyntaxNode): string {
  for (let p: SyntaxNode | null = node.parent; p; p = p.parent) {
    if (p.type === "function_declaration" || p.type === "method_definition") return p.childForFieldName("name")?.text ?? "";
    if (p.type === "arrow_function" || p.type === "function_expression" || p.type === "function") {
      const owner = p.parent;
      if (owner?.type === "variable_declarator") return owner.childForFieldName("name")?.text ?? "";
      if (owner?.type === "pair") return pairKey(owner);
      return "";
    }
  }
  return "";
}

function checkWeakCrypto(root: SyntaxNode, make: Make): void {
  for (const call of findNodes(root, (n) => n.type === "call_expression")) {
    const callee = call.childForFieldName("function");
    const args = call.childForFieldName("arguments")?.namedChildren ?? [];
    if (!callee) continue;
    const calleeText = callee.text;
    const method = callee.type === "member_expression" ? (callee.childForFieldName("property")?.text ?? "") : calleeText;
    const object = callee.type === "member_expression" ? (callee.childForFieldName("object")?.text ?? "") : "";

    // crypto.createHash("md5").update(password)
    if (method === "createHash" && /^(?:md4|md5|sha1|sha-1|ripemd160)$/i.test(stringValue(args[0]) ?? "")) {
      let subject = "";
      for (let p: SyntaxNode | null = call.parent; p && subject === ""; p = p.parent) {
        if (p.type === "call_expression" && p.childForFieldName("function")?.text.endsWith(".update")) subject = p.childForFieldName("arguments")?.text ?? "";
        if (p.type === "statement_block" || p.type === "program") break;
      }
      if (PASSWORD_NAME.test(subject) || PASSWORD_NAME.test(enclosingFunctionName(call))) {
        make("weak-crypto", "high", call, `A password is hashed with ${stringValue(args[0])?.toUpperCase()}. These hashes are made to be fast: a stolen database is cracked at billions of guesses per second. Use bcrypt, scrypt or argon2 (a slow, salted password hash).`);
      }
      continue;
    }

    // Math.random() for a token, a reset code, a session id
    if (calleeText === "Math.random") {
      const name = enclosingName(call) || enclosingFunctionName(call);
      if (SECURITY_NAME.test(name) && !NOT_SECURITY.test(name)) {
        make("weak-crypto", "medium", call, `\`${name}\` is built from Math.random(), which is predictable: someone who sees a few values can guess the next ones and take over an account. Use crypto.randomBytes(32).toString("hex") or crypto.randomUUID().`);
      }
      continue;
    }

    // bcrypt.hash(password, 4)
    if (/^(?:bcrypt|bcryptjs)$/i.test(object) && /^(?:hash|hashSync|genSalt|genSaltSync)$/.test(method)) {
      const rounds = /^gen/.test(method) ? args[0] : args[1];
      if (rounds?.type === "number" && Number(rounds.text) < 10) {
        make("weak-crypto", "medium", call, `bcrypt is run with a cost of ${rounds.text}. Below 10 a stolen database is cracked far too fast; use 12 (about a quarter of a second per password).`);
      }
      continue;
    }

    // ECB mode, DES, RC4, or createCipher (no IV, key stretched with MD5)
    if (method === "createCipheriv" && /(?:-ecb$|^des(?!-ede)|^rc[24]|^bf)/i.test(stringValue(args[0]) ?? "")) {
      make("weak-crypto", "medium", call, `The cipher ${stringValue(args[0])} is weak: ECB mode shows patterns in the data, and DES / RC4 / Blowfish are broken or outdated. Use aes-256-gcm with a random 12-byte IV per message.`);
    } else if (method === "createCipher" || method === "createDecipher") {
      make("weak-crypto", "medium", call, `crypto.${method}() derives the key with MD5 and uses no IV (it is removed in current Node.js). Use createCipheriv with aes-256-gcm and a random IV per message.`);
    }
  }
}

function checkCookies(root: SyntaxNode, make: Make): void {
  for (const call of findNodes(root, (n) => n.type === "call_expression")) {
    const callee = call.childForFieldName("function");
    const args = call.childForFieldName("arguments")?.namedChildren ?? [];
    if (!callee) continue;
    const method = callee.type === "member_expression" ? (callee.childForFieldName("property")?.text ?? "") : callee.text;

    // session({ cookie: { secure: false, httpOnly: false } }) / cookieSession({ httpOnly: false })
    if (/^(?:session|cookieSession|expressSession)$/.test(method) && args[0]?.type === "object") {
      const cookie = pairsOf(args[0]).find((p) => pairKey(p) === "cookie");
      const options = method === "cookieSession" ? args[0] : cookie?.childForFieldName("value");
      for (const pair of pairsOf(options)) {
        const key = pairKey(pair);
        if (pair.childForFieldName("value")?.text !== "false") continue;
        if (key === "httpOnly") make("insecure-cookie", "medium", pair, "The session cookie is set with httpOnly: false, so any script on the page (one XSS hole, one bad npm package) can read it and take over the session. Leave httpOnly on (true).");
        if (key === "secure") make("insecure-cookie", "medium", pair, "The session cookie is set with secure: false, so the browser sends it over plain HTTP too, where anyone on the network can read it. Use secure: true (behind a proxy also app.set('trust proxy', 1)); a local-development override belongs in an environment check.");
      }
    }

    // res.cookie("token", value, { ... })
    if (method === "cookie" && callee.type === "member_expression" && /^(?:res|response|reply)$/.test(callee.childForFieldName("object")?.text ?? "")) {
      const name = stringValue(args[0]) ?? "";
      if (!AUTH_COOKIE.test(name)) continue;
      const options = args[2];
      if (options && options.type !== "object") continue; // options kept in a variable: not seen
      const pairs = pairsOf(options);
      const httpOnly = pairs.find((p) => pairKey(p) === "httpOnly");
      const secure = pairs.find((p) => pairKey(p) === "secure");
      if (!httpOnly || httpOnly.childForFieldName("value")?.text === "false") {
        make("insecure-cookie", "medium", call, `The cookie "${name}" is set without httpOnly: true, so scripts on the page can read it (an XSS hole then hands over the login). Pass { httpOnly: true, secure: true, sameSite: "lax" }.`);
      } else if (secure?.childForFieldName("value")?.text === "false") {
        make("insecure-cookie", "medium", secure, `The cookie "${name}" is set with secure: false, so it is also sent over plain HTTP. Use secure: true in production.`);
      }
    }
  }
}

/**
 * A tool that connects only to LOOK at the certificate (an expiry monitor, `tls.connect` + `getPeerCertificate()`, no request sent) has to accept
 * invalid ones; that is the point of it. Not a hole as long as nothing is sent over the connection.
 */
function inspectsCertificate(pair: SyntaxNode): boolean {
  for (let p: SyntaxNode | null = pair.parent; p; p = p.parent) {
    if (p.type === "function_declaration" || p.type === "arrow_function" || p.type === "function_expression" || p.type === "function" || p.type === "method_definition") {
      if (/getPeerCertificate/.test(p.text) && !/\.write\(|\.request\(|\bfetch\(|\.get\(|\.post\(|axios/.test(p.text)) return true;
    }
  }
  return false;
}

function checkTls(root: SyntaxNode, make: Make): void {
  for (const pair of findNodes(root, (n) => n.type === "pair")) {
    const key = pairKey(pair);
    const value = pair.childForFieldName("value")?.text;
    if ((key === "rejectUnauthorized" || key === "strictSSL") && value === "false" && !inspectsCertificate(pair)) {
      make("tls-verification", "high", pair, `${key}: false turns off the check of the server's certificate, so anyone between you and the server can read and change the traffic. Remove it; for a self-signed development server, trust that one certificate (the ca option) instead.`);
    }
  }
  for (const assignment of findNodes(root, (n) => n.type === "assignment_expression")) {
    const left = assignment.childForFieldName("left")?.text ?? "";
    const right = assignment.childForFieldName("right");
    if (/NODE_TLS_REJECT_UNAUTHORIZED/.test(left) && (stringValue(right) === "0" || right?.text === "0" || right?.text === "false")) {
      make("tls-verification", "high", assignment, "NODE_TLS_REJECT_UNAUTHORIZED = 0 switches off certificate checks for every HTTPS request of the whole process. Remove it; trust the specific certificate (NODE_EXTRA_CA_CERTS) if you need a private authority.");
    }
  }
}

export class HardeningAnalyzer implements Analyzer {
  analyze(parsed: ParsedFile, filePath: string, _context?: ProjectContext): Finding[] {
    const text = parsed.sourceCode;
    if (!/createHash|Math\.random|bcrypt|createCipher|cookie|session|rejectUnauthorized|strictSSL|NODE_TLS/i.test(text)) return [];
    const findings: Finding[] = [];
    const seen = new Set<string>();
    const make: Make = (rule, severity, node, message) => {
      const key = `${rule}:${node.startIndex}`;
      if (seen.has(key)) return;
      seen.add(key);
      findings.push({
        ruleId: rule,
        severity,
        confidence: "medium",
        message,
        location: toLocation(node, filePath),
        sourceSnippet: "(code pattern)",
        sinkSnippet: snippet(node, text),
      });
    };
    const root = parsed.tree.rootNode;
    if (/createHash|Math\.random|bcrypt|createCipher/.test(text)) checkWeakCrypto(root, make);
    if (/cookie|session/i.test(text)) checkCookies(root, make);
    if (/rejectUnauthorized|strictSSL|NODE_TLS/.test(text)) checkTls(root, make);
    return findings;
  }
}

function isRegexSink(node: SyntaxNode): boolean {
  if (node.type !== "new_expression" && node.type !== "call_expression") return false;
  const callee = node.type === "new_expression" ? node.childForFieldName("constructor") : node.childForFieldName("function");
  return callee?.text === "RegExp";
}

/** `new RegExp(req.query.q)`: the caller writes the pattern, so a short crafted one freezes the server (ReDoS) or matches every record. */
export class RegexInjectionAnalyzer extends BaseAnalyzer {
  protected config(): AnalyzerConfig {
    return {
      ruleId: "regex-injection",
      severity: "medium",
      confidence: "medium",
      isSource: isRequestSource,
      isSink: isRegexSink,
      sinkArgs: firstArgument,
      messageFor: (via) =>
        `User-controlled input ('${via}') becomes a regular expression. A crafted pattern such as (a+)+$ makes the match take minutes and freezes the server (ReDoS), ` +
        `and a pattern like .* matches every record. Escape the text first (value.replace(/[.*+?^\${}()|[\\]\\\\]/g, "\\\\$&")) or search with a plain string.`,
    };
  }
}
