import { SyntaxNode, findNodes, snippet, toLocation } from "../parsers/utils";
import { isFixturePath } from "../analyzers/hardcoded-secret";
import { findKnownSecrets, isDemoLogin, isPlaceholder, isSensitiveName, isSigningSecretName, looksLikeSecret, normalizeName, redact } from "../secrets/detect";
import { Finding, Severity, VulnerabilityType } from "../types";
import { calleeText, callArguments } from "./engine";
import { isStringLiteral, literalValue } from "./sinks";

/**
 * The Go rules that need no data flow: weak crypto, a certificate check switched off, a login cookie without HttpOnly, debug endpoints
 * (`net/http/pprof`), unsigned JWTs, a CORS policy that trusts every site with cookies, and secrets written in the code.
 */

const SECURITY_NAME = /token|secret|otp|nonce|reset|verif|session|csrf|xsrf|passcode|password|passwd|api[_-]?key|invite|salt|signature|auth[_-]?code/i;
const NOT_SECURITY = /color|colour|delay|jitter|backoff|animation|retry|shuffle|sample|position|offset|index|angle|speed|size|pick|greeting|message|emoji|avatar|placeholder|demo|mock|fake|test/i;
const PASSWORD_NAME = /pass(?:word|wd|phrase)?\b|pwd/i;
const AUTH_COOKIE = /token|session|sid\b|auth|jwt|access|refresh|login|remember/i;
// A function whose job is to look at a connection or a certificate: it may have to accept a bad one. Reported, but with low confidence.
const DIAGNOSTIC = /test|check|probe|ping|diagnos|inspect/i;

const ROTATE =
  "Treat it as already leaked: revoke / rotate it now (removing the line is not enough: it stays in the git history), " +
  "then load the new value from an environment variable (os.Getenv(\"NAME\")) or a secret manager.";

type Make = (rule: VulnerabilityType, severity: Severity, node: SyntaxNode, message: string, confidence?: Finding["confidence"]) => void;

function enclosingFunctionName(node: SyntaxNode): string {
  for (let p: SyntaxNode | null = node.parent; p; p = p.parent) {
    if (p.type === "function_declaration" || p.type === "method_declaration") return p.childForFieldName("name")?.text ?? "";
  }
  return "";
}

/** The local name of an imported package: `import mrand "math/rand"` -> mrand, `import "math/rand"` -> rand. */
function importedAs(root: SyntaxNode, packagePath: string): string | undefined {
  for (const spec of findNodes(root, (n) => n.type === "import_spec")) {
    const target = spec.childForFieldName("path");
    if (literalValue(target ?? undefined) !== packagePath) continue;
    const alias = spec.childForFieldName("name")?.text;
    if (alias === "_" || alias === ".") return undefined;
    return alias ?? packagePath.slice(packagePath.lastIndexOf("/") + 1);
  }
  return undefined;
}

/** The fields of a struct literal by name: `http.Cookie{Name: "sid", HttpOnly: false}` -> Name, HttpOnly. */
function fieldsOf(literal: SyntaxNode): Map<string, SyntaxNode> {
  const fields = new Map<string, SyntaxNode>();
  const body = literal.childForFieldName("body");
  for (const element of body?.namedChildren ?? []) {
    if (element.type !== "keyed_element") continue;
    const key = element.namedChild(0);
    const value = element.namedChild(1);
    const keyText = key?.text;
    if (keyText && value) fields.set(keyText, value.type === "literal_element" ? (value.namedChild(0) ?? value) : value);
  }
  return fields;
}

/** True when `node` sits inside a call whose callee matches (`req.AddCookie(&http.Cookie{...})`: a cookie sent, not set). */
function insideCall(node: SyntaxNode, callee: RegExp): boolean {
  for (let p: SyntaxNode | null = node.parent; p; p = p.parent) {
    if (p.type === "function_declaration" || p.type === "method_declaration" || p.type === "func_literal") return false;
    if (p.type === "call_expression" && callee.test(p.childForFieldName("function")?.text ?? "")) return true;
  }
  return false;
}

// `if cfg.InsecureSkipVerify { ... }`, `if opts.IgnoreTLSErrors`: switched off on request of whoever configures the program
const OPT_IN = /insecure|ignore|skip|verify|allow|unsafe|disable|self.?sign|trust/i;
function optedIn(node: SyntaxNode): boolean {
  for (let p: SyntaxNode | null = node.parent; p; p = p.parent) {
    if (p.type === "function_declaration" || p.type === "method_declaration") return false;
    if (p.type === "if_statement" && OPT_IN.test(p.childForFieldName("condition")?.text ?? "")) return true;
  }
  return false;
}

function typeName(literal: SyntaxNode): string {
  return literal.childForFieldName("type")?.text.replace(/\s+/g, "").replace(/^&/, "") ?? "";
}

export function hardeningFindings(root: SyntaxNode, text: string, filePath: string, developmentFile: boolean): Finding[] {
  const findings: Finding[] = [];
  const seen = new Set<string>();
  const make: Make = (rule, severity, node, message, confidence = "medium") => {
    const key = `${rule}:${node.startIndex}`;
    if (seen.has(key)) return;
    seen.add(key);
    findings.push({ ruleId: rule, severity, confidence, message, location: toLocation(node, filePath), sourceSnippet: "(code pattern)", sinkSnippet: snippet(node, text) });
  };

  const hasHash = /md5|sha1|des\.|rc4|bcrypt|math\/rand|InsecureSkipVerify|http\.Cookie|SetCookie|HttpOnly|HTTPOnly|jwt|pprof|expvar|AllowAllOrigins|AllowCredentials|AllowedOrigins|Debug\s*=/.test(text);
  if (hasHash) {
    const mathRand = importedAs(root, "math/rand");

    for (const call of findNodes(root, (n) => n.type === "call_expression")) {
      const name = calleeText(call);
      const args = callArguments(call);

      // md5.Sum([]byte(password)), sha1.New() inside hashPassword()
      if (/^(?:md5|sha1)\.(?:Sum|New)$/.test(name)) {
        const subject = args.map((a) => a.text).join(" ");
        if (PASSWORD_NAME.test(subject) || PASSWORD_NAME.test(enclosingFunctionName(call))) {
          make("weak-crypto", "high", call, `A password is hashed with ${name.slice(0, name.indexOf("."))}. These hashes are made to be fast: a stolen database is cracked at billions of guesses per second. Use bcrypt (golang.org/x/crypto/bcrypt) or argon2id, which are slow and salted on purpose.`);
        }
      }
      // des.NewCipher, rc4.NewCipher
      if (/^(?:des|rc4)\.New\w*Cipher$/.test(name)) {
        make("weak-crypto", "medium", call, "This cipher is weak: DES and RC4 are broken or outdated. Use AES-GCM (crypto/aes with cipher.NewGCM) with a random nonce per message.");
      }
      // bcrypt.GenerateFromPassword(pw, 4)
      if (name === "bcrypt.GenerateFromPassword" && args[1]) {
        const cost = args[1].text;
        if (/^\d+$/.test(cost) ? Number(cost) < 10 : /MinCost$/.test(cost)) {
          make("weak-crypto", "medium", call, `bcrypt is run with a cost of ${cost}. Below 10 a stolen database is cracked far too fast; use bcrypt.DefaultCost (10) or 12.`);
        }
      }

      // jwt.ParseUnverified(...)
      if (/(?:^|\.)ParseUnverified$/.test(name) && /jwt/i.test(name + text.slice(0, 2000))) {
        make("insecure-jwt", "critical", call, "The JWT is read without checking its signature (ParseUnverified). Anyone can forge a token with any user id or role. Use jwt.Parse with a key function that checks the signing method, or ParseWithClaims.", "high");
      }
      // c.SetCookie(name, value, maxAge, path, domain, secure, httpOnly)  (gin)
      if (/\.SetCookie$/.test(name) && args.length >= 7) {
        const cookieName = literalValue(args[0]) ?? "";
        if (AUTH_COOKIE.test(cookieName)) {
          if (args[6]?.text === "false") make("insecure-cookie", "medium", call, `The cookie "${cookieName}" is set with httpOnly=false, so scripts on the page can read it (an XSS hole then hands over the login). Pass true as the last argument, and true for secure as well.`);
          else if (args[5]?.text === "false") make("insecure-cookie", "medium", call, `The cookie "${cookieName}" is set with secure=false, so it is also sent over plain HTTP. Use true in production.`);
        }
      }
      // rand.Intn(...) for a token
      if (mathRand && new RegExp(`^${mathRand}\\.(?:Int|Intn|Int31|Int31n|Int63|Int63n|Uint32|Uint64|Float32|Float64|Read|Perm)$`).test(name)) {
        const parent = call.parent;
        let target = "";
        if (parent?.type === "expression_list") {
          const declaration = parent.parent;
          const left = declaration?.childForFieldName("left");
          if (left && (declaration?.type === "short_var_declaration" || declaration?.type === "assignment_statement")) target = left.text;
        } else if (parent?.type === "var_spec") {
          target = parent.namedChildren.find((c) => c.type === "identifier")?.text ?? "";
        }
        const where = target || (call.parent?.type === "expression_list" && call.parent.parent?.type === "return_statement" ? enclosingFunctionName(call) : "");
        if (where && SECURITY_NAME.test(where) && !NOT_SECURITY.test(where)) {
          make("weak-crypto", "medium", call, `\`${where}\` is built with math/rand, which is predictable: someone who sees a few values can guess the next ones and take over an account. Use crypto/rand (rand.Read into a byte slice, then base64 / hex).`);
        }
      }
    }

    for (const literal of findNodes(root, (n) => n.type === "composite_literal")) {
      const type = typeName(literal);
      const fields = fieldsOf(literal);
      // tls.Config{InsecureSkipVerify: true}
      if (/(?:^|\.)Config$/.test(type) && /tls/.test(type) && fields.get("InsecureSkipVerify")?.text === "true" && !developmentFile) {
        const diagnostic = DIAGNOSTIC.test(enclosingFunctionName(literal)) || optedIn(literal);
        make("tls-verification", "high", literal, `InsecureSkipVerify: true turns off the check of the server's certificate, so anyone between you and the server can read and change the traffic. Remove it; for a private certificate authority put it in RootCAs (x509.NewCertPool).${diagnostic ? " (Reported with low confidence: it looks like an option someone chooses, or a connectivity check.)" : ""}`, diagnostic ? "low" : "medium");
      }
      // http.Cookie{Name: "session", HttpOnly: false}
      if (/^(?:http\.Cookie|fiber\.Cookie)$/.test(type) || /\.Cookie$/.test(type)) {
        const cookieName = literalValue(fields.get("Name")) ?? "";
        const httpOnly = fields.get("HttpOnly") ?? fields.get("HTTPOnly");
        const secure = fields.get("Secure");
        const clearing = fields.get("Value")?.text === '""' || fields.get("MaxAge")?.text.startsWith("-") === true;
        if (AUTH_COOKIE.test(cookieName) && !clearing && !insideCall(literal, /(?:^|\.)(?:AddCookie|SetCookies)$/)) {
          if (!httpOnly || httpOnly.text === "false") make("insecure-cookie", "medium", literal, `The cookie "${cookieName}" is set without HttpOnly: true, so scripts on the page can read it (an XSS hole then hands over the login). Add HttpOnly: true, Secure: true and SameSite: http.SameSiteLaxMode.`);
          else if (secure?.text === "false") make("insecure-cookie", "medium", literal, `The cookie "${cookieName}" is set with Secure: false, so it is also sent over plain HTTP. Use Secure: true in production.`);
        }
      }
      // sessions.Options{HttpOnly: false, Secure: false}
      if (/sessions\.Options$/.test(type) && !developmentFile) {
        if (fields.get("HttpOnly")?.text === "false") make("insecure-cookie", "medium", literal, "The session cookie is set with HttpOnly: false, so scripts on the page can read it. Use HttpOnly: true.");
        else if (fields.get("Secure")?.text === "false") make("insecure-cookie", "medium", literal, "The session cookie is set with Secure: false, so it is also sent over plain HTTP. Use Secure: true in production.");
      }
      // CORS: every site, with cookies
      if (/(?:^|\.)(?:Config|Options)$/.test(type) && /cors/i.test(type + text.slice(0, 3000)) && fields.get("AllowCredentials")?.text === "true") {
        const everyone = fields.get("AllowAllOrigins")?.text === "true" || /"\*"/.test(fields.get("AllowOrigins")?.text ?? fields.get("AllowedOrigins")?.text ?? "") || fields.get("AllowOriginFunc")?.text.includes("return true") === true;
        if (everyone) make("insecure-cors", "high", literal, "This CORS policy allows every origin and also allows credentials: any website can call the API with the visitor's cookies and read the answer. List the exact origins you trust (AllowOrigins: []string{\"https://app.example.com\"}).");
      }
    }

    // cfg.InsecureSkipVerify = true, e.Debug = true
    for (const assignment of findNodes(root, (n) => n.type === "assignment_statement")) {
      const left = assignment.childForFieldName("left");
      const right = assignment.childForFieldName("right");
      if (!left || !right) continue;
      if (/(?:^|\.)InsecureSkipVerify$/.test(left.text) && right.text === "true" && !developmentFile) {
        const diagnostic = DIAGNOSTIC.test(enclosingFunctionName(assignment)) || optedIn(assignment);
        make("tls-verification", "high", assignment, `InsecureSkipVerify = true turns off the check of the server's certificate, so anyone between you and the server can read and change the traffic. Remove it.${diagnostic ? " (Reported with low confidence: it looks like an option someone chooses, or a connectivity check.)" : ""}`, diagnostic ? "low" : "medium");
      }
      if (/^\w+\.Debug$/.test(left.text) && right.text === "true" && !developmentFile && /echo/.test(text)) {
        make("debug-mode", "medium", assignment, "Echo's Debug = true sends error details and stack traces to the client. Turn it on only locally (from an environment variable).", "low");
      }
    }
  }

  // import _ "net/http/pprof": /debug/pprof on the default mux (heap dumps, goroutine stacks, a CPU profile on request)
  for (const spec of findNodes(root, (n) => n.type === "import_spec")) {
    const target = literalValue(spec.childForFieldName("path") ?? undefined);
    if (target === "net/http/pprof" && !developmentFile) {
      make("debug-endpoint", "medium", spec, "net/http/pprof is imported: it registers /debug/pprof/ on http.DefaultServeMux, and anyone who can reach that server can download heap dumps (which hold secrets and user data), goroutine stacks and run profiles that slow it down. Serve pprof on a separate localhost-only listener (127.0.0.1:6060), or drop the import in production.", "low");
    }
  }
  return findings;
}

function strippedString(node: SyntaxNode): string | undefined {
  if (!isStringLiteral(node)) return undefined;
  return node.text.slice(1, -1);
}

/** The name a string literal is assigned to: `password := "x"`, `const apiKey = "x"`, `Config{Secret: "x"}`, `[]byte("x")` held by one of those. */
function assignedName(literal: SyntaxNode): string | undefined {
  let node: SyntaxNode = literal;
  // []byte("secret"), string("secret"), []byte("a" + "b") is not followed
  const parent = node.parent;
  if (parent && (parent.type === "type_conversion_expression" || (parent.type === "argument_list" && parent.parent?.type === "call_expression" && /^(?:string|\[\]byte)$/.test(parent.parent.childForFieldName("function")?.text ?? "")))) {
    node = parent.type === "argument_list" ? (parent.parent as SyntaxNode) : parent;
  }
  const holder = node.parent;
  if (!holder) return undefined;
  if (holder.type === "expression_list") {
    const index = holder.namedChildren.findIndex((c) => c.id === node.id);
    const declaration = holder.parent;
    if (!declaration || index === -1) return undefined;
    if (declaration.type === "short_var_declaration" || declaration.type === "assignment_statement") {
      const left = declaration.childForFieldName("left");
      const target = left?.type === "expression_list" ? left.namedChildren[index] : left;
      if (target?.type === "identifier") return target.text;
      if (target?.type === "selector_expression") return target.childForFieldName("field")?.text;
      if (target?.type === "index_expression") return strippedString(target.childForFieldName("index") as SyntaxNode) ?? undefined;
    }
    if (declaration.type === "const_spec" || declaration.type === "var_spec") {
      return declaration.namedChildren.filter((c) => c.type === "identifier")[index]?.text;
    }
  }
  if (holder.type === "literal_element" && holder.parent?.type === "keyed_element") {
    const element = holder.parent;
    if (element.namedChild(1)?.id === holder.id) return element.namedChild(0)?.text;
  }
  return undefined;
}

/** Secrets written in the code. (Seed data, fixtures and mocks hold made-up credentials on purpose: judged by path and name they are noise.) */
export function secretFindings(root: SyntaxNode, text: string, filePath: string): Finding[] {
  const findings: Finding[] = [];
  const seen = new Set<string>();
  const add = (finding: Finding): void => {
    const key = `${finding.ruleId}:${finding.location.startLine}:${finding.location.startColumn}`;
    if (seen.has(key)) return;
    seen.add(key);
    findings.push(finding);
  };
  const fixtureLike = isFixturePath(filePath);
  const lines = text.split("\n");
  for (const match of findKnownSecrets(text)) {
    if (fixtureLike && /private key/i.test(match.secret.label)) continue;
    // documentation and help text: `// redis://user:pass@host`, a placeholder or a well-known default password in an example URL
    const lineStart = text.lastIndexOf("\n", match.index) + 1;
    if (/^\s*(?:\/\/|\/\*|\*)/.test(text.slice(lineStart, match.index + 1))) continue;
    if (/:\/\/[^:/@\s]*:(?:pass(?:word)?|user|guest|admin|root|secret|changeme|example|test|dev|redis|postgres|mysql|\*+|x+)?@/i.test(match.text)) continue;
    const before = text.slice(0, match.index);
    const line = before.split("\n").length;
    const column = match.index - before.lastIndexOf("\n");
    add({
      ruleId: "hardcoded-secret",
      severity: match.secret.severity,
      confidence: "high",
      message: `A ${match.secret.label} is written into the source code (${redact(match.text)}). Anyone who can read this repository can use it. ${ROTATE}`,
      location: { file: filePath, startLine: line, startColumn: column, endLine: line, endColumn: column + match.text.length },
      sourceSnippet: redact(match.text),
      sinkSnippet: (lines[line - 1] ?? "").split(match.text).join("<redacted>").trim().slice(0, 160),
    });
  }
  for (const literal of findNodes(root, (n) => n.type === "interpreted_string_literal" || n.type === "raw_string_literal")) {
    const value = strippedString(literal);
    const rawName = value === undefined ? undefined : assignedName(literal);
    if (value === undefined || !rawName || value.length < 4) continue;
    const name = normalizeName(rawName);
    if (isPlaceholder(value) || fixtureLike) continue;
    if (/^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$/.test(value)) continue; // the NAME of an environment variable: EnvClientSecret = "APP_CLIENT_SECRET"
    const signing = isSigningSecretName(name);
    if (!signing && (!(isSensitiveName(name) && looksLikeSecret(value, name)) || isDemoLogin(text, literal.startIndex))) continue;
    if (signing && !looksLikeSecret(value, name) && value.length < 8) continue;
    add({
      ruleId: "hardcoded-secret",
      severity: "high",
      confidence: signing ? "high" : "medium",
      message: signing
        ? `\`${rawName}\` is a string written in the code (${redact(value)}) and is used to sign sessions or tokens. Anyone who reads the code can forge logins. Use a long random value from an environment variable (os.Getenv("${name.toUpperCase()}")).`
        : `\`${rawName}\` is assigned a string that looks like a real credential (${redact(value)}). ${ROTATE}`,
      location: toLocation(literal, filePath),
      sourceSnippet: redact(value),
      sinkSnippet: (lines[literal.startPosition.row] ?? "").split(value).join("<redacted>").trim().slice(0, 160),
    });
  }
  return findings;
}
