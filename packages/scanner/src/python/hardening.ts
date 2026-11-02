import { SyntaxNode, findNodes, snippet, toLocation } from "../parsers/utils";
import { Finding, Severity, VulnerabilityType } from "../types";
import { calleeText, callArguments } from "./engine";

/**
 * The Python side of weak-crypto / insecure-cookie / tls-verification (the JavaScript side and the reasoning are in
 * analyzers/hardening.ts). Plain patterns, no data flow: MD5 or SHA-1 over a password, `random` for a token, ECB mode, bcrypt with a low
 * cost, a Django password-hasher list with MD5, a login cookie without HttpOnly, `*_COOKIE_SECURE = False`, `verify=False`.
 */

const SECURITY_NAME = /token|secret|otp|nonce|reset|verif|session|csrf|xsrf|passcode|password|passwd|api[_-]?key|invite|salt|signature|auth[_-]?code/i;
const NOT_SECURITY = /color|colour|delay|jitter|backoff|animation|retry|shuffle|sample|position|offset|index|angle|speed|size|pick|greeting|message|emoji|avatar|placeholder|demo|mock|fake|test/i;
const PASSWORD_NAME = /pass(?:word|wd|phrase)?\b|pwd/i;
const AUTH_COOKIE = /token|session|sid\b|auth|jwt|access|refresh|login|remember/i;
// requests / httpx / aiohttp / urllib3 clients and sessions; not jwt.decode(verify=False), which is a different rule
const HTTP_CLIENT = /^(?:requests|httpx|aiohttp|urllib3)\.|^(?:session|sess|client|http|self\.session|self\.client|self\.http)\.(?:get|post|put|patch|delete|head|options|request|stream|send)$|^(?:get|post|put|patch|delete|request)$/;
const RANDOM_CALL = /^random\.(?:random|randint|randrange|choice|choices|getrandbits|sample|uniform)$/;

type Make = (rule: VulnerabilityType, severity: Severity, node: SyntaxNode, message: string, confidence?: Finding["confidence"]) => void;

// Code that only runs for the tests (`if "test" in sys.argv:`, `if TESTING:`) is allowed to be fast and weak.
function inTestBranch(node: SyntaxNode): boolean {
  for (let p: SyntaxNode | null = node.parent; p; p = p.parent) {
    if (p.type === "if_statement" && /test|pytest/i.test(p.childForFieldName("condition")?.text ?? "")) return true;
  }
  return false;
}

// A function whose job is to look at a connection or a certificate: it may have to accept a bad one. Reported, but with low confidence.
const DIAGNOSTIC = /test|check|probe|ping|diagnos|inspect/i;

function literal(node: SyntaxNode | null | undefined): string | undefined {
  if (!node || node.type !== "string") return undefined;
  return node.text.replace(/^[rbfuRBFU]*("""|'''|"|')/, "").replace(/("""|'''|"|')$/, "");
}

function enclosingFunctionName(node: SyntaxNode): string {
  for (let p: SyntaxNode | null = node.parent; p; p = p.parent) if (p.type === "function_definition") return p.childForFieldName("name")?.text ?? "";
  return "";
}

export function hardeningFindings(root: SyntaxNode, text: string, filePath: string, developmentFile: boolean): Finding[] {
  if (!/hashlib|random|MODE_ECB|DES\.|ARC[24]|Blowfish|gensalt|PASSWORD_HASHERS|set_cookie|COOKIE|verify|_create_unverified|CERT_NONE|check_hostname/.test(text)) return [];
  const findings: Finding[] = [];
  const seen = new Set<string>();
  const make: Make = (rule, severity, node, message, confidence = "medium") => {
    const key = `${rule}:${node.startIndex}`;
    if (seen.has(key)) return;
    seen.add(key);
    findings.push({ ruleId: rule, severity, confidence, message, location: toLocation(node, filePath), sourceSnippet: "(code pattern)", sinkSnippet: snippet(node, text) });
  };

  for (const call of findNodes(root, (n) => n.type === "call")) {
    const name = calleeText(call);
    const { positional, keywords } = callArguments(call);

    // hashlib.md5(password.encode()) / hashlib.new("md5", pw)
    const hashName = name === "hashlib.new" ? literal(positional[0])?.toLowerCase() : /^hashlib\.(md5|sha1)$/.test(name) ? name.slice(8) : undefined;
    if (hashName && /^(?:md5|sha1)$/.test(hashName)) {
      const subject = (name === "hashlib.new" ? positional.slice(1) : positional).map((a) => a.text).join(" ");
      if (PASSWORD_NAME.test(subject) || PASSWORD_NAME.test(enclosingFunctionName(call))) {
        make("weak-crypto", "high", call, `A password is hashed with ${hashName.toUpperCase()}. These hashes are made to be fast: a stolen database is cracked at billions of guesses per second. Use bcrypt, argon2 or Django's make_password (a slow, salted hash).`);
      }
    }

    // AES.new(key, AES.MODE_ECB), DES.new, ARC4.new, Blowfish.new
    if (/\.new$/.test(name) && (/MODE_ECB/.test(call.text) || /^(?:DES|ARC4|ARC2|Blowfish|CAST)\.new$/.test(name))) {
      make("weak-crypto", "medium", call, "This cipher is weak: ECB mode shows patterns in the data, and DES / RC4 / Blowfish are broken or outdated. Use AES-GCM (cryptography's AESGCM) with a random 12-byte nonce per message.");
    }

    // bcrypt.gensalt(rounds=4)
    if (/(?:^|\.)gensalt$/.test(name) && /bcrypt/.test(name)) {
      const rounds = keywords.get("rounds") ?? positional[0];
      if (rounds?.type === "integer" && Number(rounds.text) < 10) make("weak-crypto", "medium", call, `bcrypt is run with a cost of ${rounds.text}. Below 10 a stolen database is cracked far too fast; use 12.`);
    }

    // response.set_cookie("token", value) without httponly=True
    if (/(?:^|\.)set_cookie$/.test(name)) {
      const cookieName = literal(positional[0] ?? keywords.get("key")) ?? "";
      const splat = (call.childForFieldName("arguments")?.namedChildren ?? []).some((a) => a.type === "dictionary_splat");
      if (AUTH_COOKIE.test(cookieName) && !splat) {
        const httponly = keywords.get("httponly")?.text;
        const secure = keywords.get("secure")?.text;
        if (httponly !== "True") make("insecure-cookie", "medium", call, `The cookie "${cookieName}" is set without httponly=True, so scripts on the page can read it (an XSS hole then hands over the login). Pass httponly=True, secure=True, samesite="Lax".`);
        else if (secure === "False") make("insecure-cookie", "medium", call, `The cookie "${cookieName}" is set with secure=False, so it is also sent over plain HTTP. Use secure=True in production.`);
      }
    }

    // requests.get(url, verify=False), client.post(..., verify=False), ssl._create_unverified_context()
    if (keywords.get("verify")?.text === "False" && HTTP_CLIENT.test(name) && !/jwt/i.test(name)) {
      const diagnostic = DIAGNOSTIC.test(enclosingFunctionName(call));
      make("tls-verification", "high", call, `verify=False turns off the check of the server's certificate, so anyone between you and the server can read and change the traffic. Remove it; for a private certificate authority pass verify='/path/ca.pem'.${diagnostic ? " (Reported with low confidence: this function looks like a connection test.)" : ""}`, diagnostic ? "low" : "medium");
    }
    if (/(?:^|\.)_create_unverified_context$/.test(name)) {
      make("tls-verification", "high", call, "ssl._create_unverified_context() builds a context that accepts any certificate, so anyone on the network path can read and change the traffic. Use ssl.create_default_context() (and cafile= for a private authority).");
    }
  }

  for (const assignment of findNodes(root, (n) => n.type === "assignment")) {
    const left = assignment.childForFieldName("left");
    const right = assignment.childForFieldName("right");
    if (!left || !right) continue;
    const target = left.type === "subscript" ? (literal(left.childForFieldName("subscript")) ?? left.text) : left.text; // app.config["SESSION_COOKIE_SECURE"]
    const targetName = target.replace(/^.*\./, "");

    // token = random.randint(...) / def make_reset_code(): return random.choice(...)
    const callsRandom = findNodes(right, (n) => n.type === "call" && RANDOM_CALL.test(calleeText(n))).length > 0;
    if (callsRandom && SECURITY_NAME.test(targetName) && !NOT_SECURITY.test(targetName)) {
      make("weak-crypto", "medium", assignment, `\`${targetName}\` is built with the random module, which is predictable: someone who sees a few values can guess the next ones and take over an account. Use secrets.token_urlsafe(32) (or secrets.choice).`);
    }

    // Django / Flask settings
    if (!developmentFile && !inTestBranch(assignment) && right.type === "false" && /^(?:SESSION_COOKIE_SECURE|CSRF_COOKIE_SECURE|SESSION_COOKIE_HTTPONLY|REMEMBER_COOKIE_HTTPONLY|REMEMBER_COOKIE_SECURE)$/.test(targetName)) {
      make("insecure-cookie", "medium", assignment, `${targetName} = False: ${/HTTPONLY/.test(targetName) ? "scripts on the page can read the login cookie (an XSS hole then hands over the session)" : "the cookie is also sent over plain HTTP, where anyone on the network can read it"}. Leave it True (the default for HTTPONLY) and read the secure flag from the environment if you need a local override.`);
    }
    const firstHasher = right.type === "list" ? (literal(right.namedChild(0)) ?? "") : "";
    if (/^PASSWORD_HASHERS$/.test(targetName) && /MD5PasswordHasher|SHA1PasswordHasher|UnsaltedMD5|UnsaltedSHA1|CryptPasswordHasher/.test(firstHasher) && !developmentFile && !inTestBranch(assignment)) {
      make("weak-crypto", "high", assignment, "PASSWORD_HASHERS starts with a fast or unsalted hash (MD5 / SHA-1 / crypt), and the first entry is the one new passwords are hashed with. Put PBKDF2, Argon2 or bcrypt first; weak hashers may stay later in the list only to verify (and upgrade) old hashes.");
    }
    // ssl_context.verify_mode = ssl.CERT_NONE / check_hostname = False
    if (/(?:^|\.)verify_mode$/.test(left.text) && /CERT_NONE/.test(right.text)) {
      make("tls-verification", "high", assignment, "verify_mode = ssl.CERT_NONE accepts any certificate, so anyone on the network path can read and change the traffic. Use ssl.CERT_REQUIRED (the default of create_default_context).");
    }
    if (/(?:^|\.)check_hostname$/.test(left.text) && right.type === "false") {
      make("tls-verification", "high", assignment, "check_hostname = False accepts a valid certificate that belongs to another site. Leave it True.");
    }
  }

  // def make_token(): return random.random(): the function's own name says what the value is
  for (const ret of findNodes(root, (n) => n.type === "return_statement")) {
    const name = enclosingFunctionName(ret);
    if (!SECURITY_NAME.test(name) || NOT_SECURITY.test(name)) continue;
    if (findNodes(ret, (n) => n.type === "call" && RANDOM_CALL.test(calleeText(n))).length > 0) {
      make("weak-crypto", "medium", ret, `${name}() returns a value built with the random module, which is predictable. Use secrets.token_urlsafe(32).`);
    }
  }
  return findings;
}
