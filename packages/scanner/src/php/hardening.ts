import { SyntaxNode, findNodes, snippet, toLocation } from "../parsers/utils";
import { Finding, Severity, VulnerabilityType } from "../types";
import { argumentsOf, calleeName } from "./engine";

/**
 * The PHP side of weak-crypto / insecure-cookie / tls-verification (reasoning in analyzers/hardening.ts): `md5($password)`, `rand()` for a
 * token, `aes-128-ecb`, a low `password_hash` cost, `setcookie("token", ...)` without the httponly argument, cURL / Guzzle with certificate
 * verification off.
 */

const SECURITY_NAME = /token|secret|otp|nonce|reset|verif|session|csrf|xsrf|passcode|password|passwd|api[_-]?key|invite|salt|signature|auth[_-]?code/i;
const NOT_SECURITY = /color|colour|delay|jitter|backoff|animation|retry|shuffle|sample|position|offset|index|angle|speed|size|pick|greeting|message|emoji|avatar|placeholder|demo|mock|fake|test/i;
const PASSWORD_NAME = /pass(?:word|wd|phrase)?\b|pwd/i;
const AUTH_COOKIE = /token|session|sid\b|auth|jwt|access|refresh|login|remember/i;
const PREDICTABLE = new Set(["rand", "mt_rand", "uniqid", "lcg_value", "srand", "mt_srand"]);
// A function whose job is to look at a connection or a certificate: it may have to accept a bad one. Reported, but with low confidence.
const DIAGNOSTIC = /test|check|probe|ping|diagnos|inspect/i;

type Make = (rule: VulnerabilityType, severity: Severity, node: SyntaxNode, message: string, confidence?: Finding["confidence"]) => void;

function stringValue(node: SyntaxNode | null | undefined): string | undefined {
  if (!node) return undefined;
  if (node.type === "string" || node.type === "encapsed_string") return node.text.slice(1, -1);
  return undefined;
}

function isFalse(node: SyntaxNode | null | undefined): boolean {
  return !!node && /^(?:false|0|["']0["']|null)$/i.test(node.text.trim());
}

function enclosingFunctionName(node: SyntaxNode): string {
  for (let p: SyntaxNode | null = node.parent; p; p = p.parent) {
    if (p.type === "function_definition" || p.type === "method_declaration") return p.childForFieldName("name")?.text ?? "";
  }
  return "";
}

export function hardeningFindings(root: SyntaxNode, text: string, filePath: string): Finding[] {
  if (!/md5|sha1|rand|uniqid|openssl_encrypt|mcrypt|password_hash|setcookie|cookie_httponly|CURLOPT_SSL|verify|crypt/i.test(text)) return [];
  const findings: Finding[] = [];
  const seen = new Set<string>();
  const make: Make = (rule, severity, node, message, confidence = "medium") => {
    const key = `${rule}:${node.startIndex}`;
    if (seen.has(key)) return;
    seen.add(key);
    findings.push({ ruleId: rule, severity, confidence, message, location: toLocation(node, filePath), sourceSnippet: "(code pattern)", sinkSnippet: snippet(node, text) });
  };

  for (const call of findNodes(root, (n) => n.type === "function_call_expression")) {
    const name = calleeName(call).toLowerCase();
    const args = argumentsOf(call);

    // md5($password), sha1($_POST['password']), hash('md5', $password)
    const algorithm = name === "md5" || name === "sha1" ? name : name === "hash" && /^(?:md5|sha1)$/i.test(stringValue(args[0]) ?? "") ? (stringValue(args[0]) as string).toLowerCase() : undefined;
    if (algorithm) {
      const subject = (name === "hash" ? args.slice(1) : args).map((a) => a.text).join(" ");
      if (PASSWORD_NAME.test(subject) || PASSWORD_NAME.test(enclosingFunctionName(call))) {
        make("weak-crypto", "high", call, `A password is hashed with ${algorithm.toUpperCase()}. These hashes are made to be fast: a stolen database is cracked at billions of guesses per second. Use password_hash($password, PASSWORD_DEFAULT) and password_verify().`);
      }
    }

    // openssl_encrypt($data, "aes-128-ecb", ...), mcrypt_*
    if (name === "openssl_encrypt" && /(?:-ecb$|^des(?!-ede)|^rc[24]|^bf)/i.test(stringValue(args[1]) ?? "")) {
      make("weak-crypto", "medium", call, `The cipher ${stringValue(args[1])} is weak: ECB mode shows patterns in the data, and DES / RC4 / Blowfish are broken or outdated. Use aes-256-gcm with a random IV (random_bytes) per message.`);
    }
    if (/^mcrypt_/.test(name)) {
      make("weak-crypto", "medium", call, "mcrypt is removed from PHP (and defaults to weak ciphers). Use openssl_encrypt with aes-256-gcm or sodium_crypto_secretbox.");
    }

    // password_hash($p, PASSWORD_BCRYPT, ["cost" => 4])
    if (name === "password_hash" && args[2]?.type === "array_creation_expression") {
      const cost = /['"]cost['"]\s*=>\s*(\d+)/.exec(args[2].text);
      if (cost && Number(cost[1]) < 10) make("weak-crypto", "medium", call, `password_hash runs with a cost of ${cost[1]}. Below 10 a stolen database is cracked far too fast; use 12 (or leave the default).`);
    }

    // setcookie("token", $value) without the httponly argument; setcookie("token", $v, ["httponly" => false])
    if (name === "setcookie" || name === "setrawcookie") {
      const cookieName = stringValue(args[0]) ?? "";
      if (AUTH_COOKIE.test(cookieName)) {
        const options = args[2]?.type === "array_creation_expression" ? args[2].text : undefined;
        const httponly = options ? /['"]httponly['"]\s*=>\s*true/i.test(options) : args[6] !== undefined && !isFalse(args[6]);
        const named = call.text.match(/httponly\s*:\s*(\w+)/i);
        if (!httponly && !(named && named[1]?.toLowerCase() === "true")) {
          make("insecure-cookie", "medium", call, `The cookie "${cookieName}" is set without the httponly flag, so scripts on the page can read it (an XSS hole then hands over the login). Pass ["httponly" => true, "secure" => true, "samesite" => "Lax"] as the third argument.`);
        }
      }
    }

    // ini_set("session.cookie_httponly", 0)
    if (name === "ini_set" && /session\.cookie_httponly/.test(args[0]?.text ?? "") && isFalse(args[1])) {
      make("insecure-cookie", "medium", call, "session.cookie_httponly is switched off, so scripts on the page can read the session cookie. Leave it on (1).");
    }

    // curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false)
    if (name === "curl_setopt" && /^CURLOPT_SSL_VERIFY(?:PEER|HOST)$/.test(args[1]?.text ?? "") && isFalse(args[2])) {
      make("tls-verification", "high", call, `${args[1]?.text} is switched off: cURL accepts any certificate, so anyone between you and the server can read and change the traffic. Leave it on (VERIFYPEER true, VERIFYHOST 2) and pass the private authority with CURLOPT_CAINFO if you need one.`);
    }
  }

  // rand()/mt_rand()/uniqid() for a token, a code, a session id:  $token = md5(uniqid()) / mt_rand()
  for (const assignment of findNodes(root, (n) => n.type === "assignment_expression")) {
    const left = assignment.childForFieldName("left");
    const right = assignment.childForFieldName("right");
    if (!left || !right) continue;
    const key = left.type === "subscript_expression" ? stringValue(left.namedChild(1)) : undefined;
    const target = key ?? left.text.replace(/^\$/, "").replace(/\[.*$/, "");
    if (left.type === "subscript_expression" && key === undefined) continue; // a variable key: nothing to judge by
    if (!SECURITY_NAME.test(target) || NOT_SECURITY.test(target)) continue;
    const predictable = findNodes(right, (n) => n.type === "function_call_expression" && PREDICTABLE.has(calleeName(n).toLowerCase()));
    const secure = findNodes(right, (n) => n.type === "function_call_expression" && /^(?:random_bytes|random_int|openssl_random_pseudo_bytes)$/.test(calleeName(n).toLowerCase()));
    if (predictable.length > 0 && secure.length === 0) {
      make("weak-crypto", "medium", assignment, `\`${key ? `$${left.namedChild(0)?.text.replace(/^\$/, "")}['${key}']` : `$${target}`}\` is built with ${calleeName(predictable[0] as SyntaxNode)}(), which is predictable: someone who sees a few values can guess the next ones and take over an account. Use bin2hex(random_bytes(32)).`);
    }
  }

  // array form: ["verify" => false] (Guzzle), "verify_peer" => false (stream context), CURLOPT_SSL_VERIFYPEER => false
  for (const element of findNodes(root, (n) => n.type === "array_element_initializer")) {
    const [key, value] = element.namedChildren;
    if (!key || !value) continue;
    const keyText = stringValue(key) ?? key.text;
    if (/^(?:verify|verify_peer|verify_peer_name|CURLOPT_SSL_VERIFYPEER|CURLOPT_SSL_VERIFYHOST)$/.test(keyText) && isFalse(value) && value.text.toLowerCase() !== "null") {
      const diagnostic = DIAGNOSTIC.test(enclosingFunctionName(element));
      make("tls-verification", "high", element, `${keyText} => false turns off the check of the server's certificate, so anyone between you and the server can read and change the traffic. Remove it; pass the private authority's certificate ('verify' => '/path/ca.pem') if you need one.${diagnostic ? ' (Reported with low confidence: this function looks like a connection test.)' : ''}`, diagnostic ? "low" : "medium");
    }
  }
  return findings;
}
