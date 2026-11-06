import { SyntaxNode, findNodes, snippet, toLocation } from "../parsers/utils";
import { isFixturePath } from "../analyzers/hardcoded-secret";
import { findKnownSecrets, isDemoLogin, isPlaceholder, isSensitiveName, isSigningSecretName, looksLikeSecret, normalizeName, redact } from "../secrets/detect";
import { Finding, Severity, VulnerabilityType } from "../types";
import { argumentsOf, callInfo } from "./engine";
import { isStringLiteral, literalValue } from "./sinks";

/**
 * The Java rules that need no data flow: weak crypto, certificate and host-name checks switched off, login cookies, Spring Security with CSRF
 * protection off or every route open, a CORS policy that trusts every site with cookies, unsigned JWTs, Jackson default typing and XML
 * parsers that resolve external entities, and secrets written in the code.
 */

const SECURITY_NAME = /token|secret|otp|nonce|reset|verif|session|csrf|xsrf|passcode|password|passwd|api[_-]?key|invite|salt|signature|auth[_-]?code/i;
const NOT_SECURITY = /color|colour|delay|jitter|backoff|animation|retry|shuffle|sample|position|offset|index|angle|speed|size|pick|greeting|message|emoji|avatar|placeholder|demo|mock|fake|test/i;
const PASSWORD_NAME = /pass(?:word|wd|phrase)?\b|pwd|credential/i;
const AUTH_COOKIE = /token|session|sid\b|auth|jwt|access|refresh|login|remember/i;
const DIAGNOSTIC = /test|check|probe|ping|diagnos|inspect/i;
const WEB_FILE = /HttpServletRequest|@RequestBody|@RequestParam|@PathVariable|@RestController|@Controller|@QueryParam|@Path\b/;

const ROTATE =
  "Treat it as already leaked: revoke / rotate it now (removing the line is not enough: it stays in the git history), " +
  "then load the new value from an environment variable (System.getenv(\"NAME\")), Spring's @Value(\"${name}\") or a secret manager.";

type Make = (rule: VulnerabilityType, severity: Severity, node: SyntaxNode, message: string, confidence?: Finding["confidence"]) => void;

function enclosingMethod(node: SyntaxNode): SyntaxNode | undefined {
  for (let p: SyntaxNode | null = node.parent; p; p = p.parent) if (p.type === "method_declaration" || p.type === "constructor_declaration") return p;
  return undefined;
}

function enclosingMethodName(node: SyntaxNode): string {
  return enclosingMethod(node)?.childForFieldName("name")?.text ?? "";
}

/** A string literal, or `"literal".getBytes(...)`: the text written in the code. */
function literalOf(node: SyntaxNode | undefined): string | undefined {
  if (!node) return undefined;
  if (isStringLiteral(node)) return literalValue(node);
  if (node.type === "method_invocation" && /^(?:getBytes|toCharArray|trim|toString)$/.test(node.childForFieldName("name")?.text ?? "")) return literalOf(node.childForFieldName("object") ?? undefined);
  if (node.type === "object_creation_expression" && node.childForFieldName("type")?.text === "String") return literalOf(argumentsOf(node)[0]);
  return undefined;
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
  const webFile = WEB_FILE.test(text);
  const stateless = /SessionCreationPolicy\.STATELESS|STATELESS/.test(text);

  for (const call of findNodes(root, (n) => n.type === "method_invocation" || n.type === "object_creation_expression")) {
    const info = callInfo(call);
    if (!info) continue;
    const { name, receiver, args, isNew } = info;
    const first = args[0];
    const method = enclosingMethod(call);

    // MessageDigest.getInstance("MD5") in code that deals with passwords
    if (!isNew && name === "getInstance" && receiver === "MessageDigest") {
      const algorithm = (literalOf(first) ?? "").toUpperCase().replace(/-/g, "");
      if (algorithm === "MD5" || algorithm === "SHA1") {
        const context = `${enclosingMethodName(call)} ${method?.text ?? ""}`;
        if (PASSWORD_NAME.test(context.slice(0, 4000))) {
          make("weak-crypto", "high", call, `A password is hashed with ${algorithm === "MD5" ? "MD5" : "SHA-1"}. These hashes are made to be fast: a stolen database is cracked at billions of guesses per second. Use BCryptPasswordEncoder / Argon2PasswordEncoder (Spring Security), or BCrypt.hashpw.`);
        }
      }
    }
    // Cipher.getInstance("DES"), "AES" (ECB by default), "AES/ECB/PKCS5Padding", RC4
    if (!isNew && name === "getInstance" && receiver === "Cipher") {
      const transformation = literalOf(first) ?? "";
      if (/^(?:DES|DESede|RC4|ARCFOUR|Blowfish|RC2)\b/i.test(transformation) || /\/ECB\//i.test(transformation) || /^AES$/i.test(transformation)) {
        make("weak-crypto", "medium", call, `Cipher "${transformation}" is weak: ECB mode (the default for plain "AES") shows patterns in the data, and DES / RC4 / Blowfish are broken or outdated. Use "AES/GCM/NoPadding" with a random 12-byte IV per message.`);
      }
    }
    // BCrypt.gensalt(4), new BCryptPasswordEncoder(4)
    if ((!isNew && name === "gensalt" && /BCrypt/.test(receiver)) || (isNew && name === "BCryptPasswordEncoder")) {
      const cost = args.find((a) => /^\d+$/.test(a.text));
      if (cost && Number(cost.text) < 10) make("weak-crypto", "medium", call, `bcrypt is run with a cost of ${cost.text}. Below 10 a stolen database is cracked far too fast; use 12.`);
    }
    // JWT without a signature check
    if (!isNew && /^(?:parseClaimsJwt|parsePlaintextJwt|parseUnsecuredClaims|parseUnsecuredContent)$/.test(name)) {
      make("insecure-jwt", "critical", call, "The JWT is parsed as an UNSIGNED token (parseClaimsJwt / parseUnsecured...): anyone can forge a token with any user id or role. Use parseClaimsJws (parseSignedClaims) with the signing key.", "high");
    }
    if (!isNew && name === "decode" && receiver === "JWT" && webFile) {
      make("insecure-jwt", "high", call, "JWT.decode(token) reads a token WITHOUT checking its signature. Anyone can forge one with any user id or role. Use JWT.require(algorithm).build().verify(token).", "medium");
    }
    if (!isNew && /SignatureAlgorithm\.NONE|Algorithm\.none\(\)/.test(call.text) && name !== "NONE") {
      make("insecure-jwt", "critical", call, 'The "none" algorithm accepts tokens with no signature at all. Use a real signing algorithm (HS256 with a long random key, or RS256).', "high");
    }
    // Jackson default typing: any class in the JSON is instantiated
    if (!isNew && /^(?:enableDefaultTyping|activateDefaultTyping)$/.test(name) && !/SecurityJackson2Modules/.test(receiver)) {
      make("insecure-deserialization", "high", call, "Jackson default typing lets the JSON name the class to create, which with common libraries on the classpath means remote code execution. Remove it, and put @JsonTypeInfo on the few types that need it with an explicit allow-list (PolymorphicTypeValidator).", webFile ? "medium" : "low");
    }
    // Hostnames and certificates: see the field / constructor scan below
    if (!isNew && /^(?:setHostnameVerifier|setDefaultHostnameVerifier)$/.test(name) && first?.type === "lambda_expression" && /->\s*true\s*$|->\s*\{\s*return\s+true;\s*\}\s*$/.test(first.text) && !developmentFile) {
      make("tls-verification", "high", call, "The host-name check is replaced by one that always says yes, so a valid certificate of another site is accepted. Remove it.", "medium");
    }
    // new Cookie("session", value) without setHttpOnly(true)
    if (isNew && name === "Cookie" && !developmentFile) {
      const cookieName = literalOf(first) ?? "";
      if (AUTH_COOKIE.test(cookieName) && literalOf(args[1]) !== "") {
        const declarator = call.parent?.type === "variable_declarator" ? call.parent : undefined;
        const variable = declarator?.childForFieldName("name")?.text;
        const scope = method?.text ?? text;
        if (variable) {
          if (!new RegExp(`\\b${variable}\\.setHttpOnly\\(\\s*true\\s*\\)`).test(scope)) make("insecure-cookie", "medium", call, `The cookie "${cookieName}" is set without setHttpOnly(true), so scripts on the page can read it (an XSS hole then hands over the login). Call setHttpOnly(true) and setSecure(true).`);
          else if (new RegExp(`\\b${variable}\\.setSecure\\(\\s*false\\s*\\)`).test(scope)) make("insecure-cookie", "medium", call, `The cookie "${cookieName}" is set with setSecure(false), so it is also sent over plain HTTP. Use setSecure(true) in production.`);
        }
      }
    }
    if (!isNew && name === "from" && receiver === "ResponseCookie" && !developmentFile) {
      const cookieName = literalOf(first) ?? "";
      let chain: SyntaxNode | null = call;
      let httpOnly = false;
      for (let hop = 0; chain && hop < 12; hop++, chain = chain.parent?.type === "method_invocation" && chain.parent.childForFieldName("object")?.id === chain.id ? chain.parent : null) {
        if (chain.type === "method_invocation" && chain.childForFieldName("name")?.text === "httpOnly" && argumentsOf(chain)[0]?.text === "true") httpOnly = true;
      }
      if (AUTH_COOKIE.test(cookieName) && !httpOnly) make("insecure-cookie", "medium", call, `The cookie "${cookieName}" is built without .httpOnly(true), so scripts on the page can read it. Add .httpOnly(true).secure(true).sameSite("Lax").`);
    }
    // Spring Security: csrf().disable()
    if (!isNew && name === "disable" && /(?:^|\.)csrf\(\)$/.test(receiver) && !developmentFile) {
      make("csrf", "medium", call, `Spring Security's CSRF protection is switched off. If a browser session (a cookie) logs users in, another site can make the browser send state-changing requests. ${stateless ? "(Reported with low confidence: the app is configured as stateless, where a token in a header replaces the cookie.) " : ""}Leave it on, or keep it off only for an API that authenticates with a token in the Authorization header and sets no session.`, stateless ? "low" : "medium");
    }
    if (!isNew && name === "csrf" && args.some((a) => /disable\b/.test(a.text)) && !developmentFile) {
      make("csrf", "medium", call, `Spring Security's CSRF protection is switched off. If a browser session (a cookie) logs users in, another site can make the browser send state-changing requests. ${stateless ? "(Reported with low confidence: the app is configured as stateless.) " : ""}Leave it on, or keep it off only for a token-authenticated API.`, stateless ? "low" : "medium");
    }
    // Spring Security: every request allowed
    if (!isNew && name === "permitAll" && /(?:anyRequest\(\)|requestMatchers\("\/\*\*"\)|antMatchers\("\/\*\*"\)|authorizeRequests\(\)\.anyRequest\(\))$/.test(receiver) && !developmentFile) {
      make("broken-access-control", "medium", call, "anyRequest().permitAll() leaves every route open, including the ones that change or read private data. List the public routes explicitly and require authentication (anyRequest().authenticated()) for the rest.", "low");
    }
    // CORS: every origin, with credentials
    if (!isNew && /^(?:allowedOrigins|allowedOriginPatterns|setAllowedOrigins|setAllowedOriginPatterns|addAllowedOrigin|addAllowedOriginPattern)$/.test(name) && args.some((a) => /^"\*"$|\{\s*"\*"\s*\}/.test(a.text) || /asList\("\*"\)|List\.of\("\*"\)/.test(a.text))) {
      if (/(?:allowCredentials|setAllowCredentials)\(\s*true\s*\)/.test(text) && !developmentFile) {
        make("insecure-cors", "high", call, "This CORS policy allows every origin and also allows credentials: any website can call the API with the visitor's cookies and read the answer. List the exact origins you trust (allowedOrigins(\"https://app.example.com\")).");
      }
    }
    // XML parsers that resolve external entities
    if (!isNew && name === "newInstance" && /^(?:DocumentBuilderFactory|SAXParserFactory|XMLInputFactory|TransformerFactory|SchemaFactory|SAXTransformerFactory)$/.test(receiver) && !developmentFile) {
      if (!/disallow-doctype-decl|FEATURE_SECURE_PROCESSING|ACCESS_EXTERNAL_DTD|ACCESS_EXTERNAL_STYLESHEET|IS_SUPPORTING_EXTERNAL_ENTITIES|external-general-entities|setExpandEntityReferences\(\s*false|SUPPORT_DTD/.test(text)) {
        make("xxe", "high", call, `${receiver}.newInstance() is used without switching off DTDs and external entities. An XML document from outside can then read local files (file:///etc/passwd) or call internal URLs. Set factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true) (and XMLConstants.FEATURE_SECURE_PROCESSING).`, webFile ? "medium" : "low");
      }
    }
    // Signing keys written in the call: Algorithm.HMAC256("secret"), signWith(key, "secret"), hmacShaKeyFor("secret".getBytes())
    if ((!isNew && /^(?:HMAC256|HMAC384|HMAC512|setSigningKey|hmacShaKeyFor|signWith|setSubject_)$/.test(name)) || (isNew && name === "SecretKeySpec")) {
      const literal = args.map(literalOf).find((v) => v !== undefined && v.length >= 6 && !/^(?:HS256|HS384|HS512|AES|HmacSHA\d+|RSA|DES)$/i.test(v));
      if (literal !== undefined && !isPlaceholder(literal) && !isFixturePath(filePath) && !developmentFile) {
        make("hardcoded-secret", "high", call, `A signing / encryption key is written in the code (${redact(literal)}) and is used to sign or encrypt data. Anyone who reads the code can forge tokens or decrypt data. ${ROTATE}`, "high");
      }
    }
    // random numbers for tokens
    if (!isNew && /^(?:Math\.random|ThreadLocalRandom\.current\(\)\.next\w+|random\.next\w+)$/.test(receiver ? `${receiver}.${name}` : name) || (isNew && name === "Random")) {
      const declarator = call.parent?.type === "variable_declarator" ? call.parent : call.parent?.type === "assignment_expression" ? call.parent : undefined;
      const target = declarator?.childForFieldName("name")?.text ?? declarator?.childForFieldName("left")?.text ?? "";
      const where = target || (call.parent?.type === "return_statement" ? enclosingMethodName(call) : "");
      if (where && SECURITY_NAME.test(where) && !NOT_SECURITY.test(where)) {
        make("weak-crypto", "medium", call, `\`${where}\` is built with java.util.Random / Math.random, which is predictable: someone who sees a few values can guess the next ones and take over an account. Use SecureRandom (and Base64 / hex of its bytes).`);
      }
    }
  }
  // NoopHostnameVerifier.INSTANCE, SSLConnectionSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER, new TrustSelfSignedStrategy(): any certificate or host name accepted
  for (const node of findNodes(root, (n) => n.type === "field_access" || n.type === "object_creation_expression")) {
    if (developmentFile) break;
    if (!/^(?:new\s+)?(?:\w+\.)*(?:NoopHostnameVerifier|TrustAllStrategy|TrustSelfSignedStrategy|InsecureTrustManagerFactory|AllowAllHostnameVerifier)\b|\bALLOW_ALL_HOSTNAME_VERIFIER\b/.test(node.text)) continue;
    if (node.parent?.type === "field_access" && node.parent.childForFieldName("object")?.id === node.id) continue; // the outer one is reported
    const diagnostic = DIAGNOSTIC.test(enclosingMethodName(node));
    make("tls-verification", "high", node, `The HTTP client is set up to accept any certificate or host name, so anyone between you and the server can read and change the traffic. Remove it; for a private certificate authority load it into a trust store (SSLContextBuilder.loadTrustMaterial(trustStore, null)).${diagnostic ? " (Reported with low confidence: the method looks like a connectivity check.)" : ""}`, diagnostic ? "low" : "medium");
  }
  // empty checkServerTrusted(): every certificate is trusted
  for (const method of findNodes(root, (n) => n.type === "method_declaration")) {
    const name = method.childForFieldName("name")?.text;
    if ((name === "checkServerTrusted" || name === "checkClientTrusted") && !developmentFile) {
      const body = method.childForFieldName("body");
      const statements = body?.namedChildren.filter((c) => c.type !== "line_comment" && c.type !== "block_comment") ?? [];
      if (body && statements.length === 0) make("tls-verification", "high", method, `${name}() does nothing, so this trust manager accepts every certificate: anyone between you and the server can read and change the traffic. Delete the custom trust manager (the default one checks certificates), or load your private authority into a trust store.`);
    }
  }
  return findings;
}

function assignedName(literal: SyntaxNode): string | undefined {
  const parent = literal.parent;
  if (!parent) return undefined;
  if (parent.type === "variable_declarator" && parent.childForFieldName("value")?.id === literal.id) return parent.childForFieldName("name")?.text;
  if (parent.type === "assignment_expression" && parent.childForFieldName("right")?.id === literal.id) {
    const left = parent.childForFieldName("left");
    if (left?.type === "identifier") return left.text;
    if (left?.type === "field_access") return left.childForFieldName("field")?.text;
  }
  if (parent.type === "element_value_pair" && parent.childForFieldName("value")?.id === literal.id) return parent.childForFieldName("key")?.text;
  // "secret".getBytes() held by a name
  if (parent.type === "method_invocation" && parent.childForFieldName("object")?.id === literal.id && /^(?:getBytes|toCharArray)$/.test(parent.childForFieldName("name")?.text ?? "")) {
    const holder = parent.parent;
    if (holder?.type === "variable_declarator") return holder.childForFieldName("name")?.text;
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
    const lineStart = text.lastIndexOf("\n", match.index) + 1;
    if (/^\s*(?:\/\/|\/\*|\*)/.test(text.slice(lineStart, match.index + 1))) continue; // documentation
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
  for (const literal of findNodes(root, (n) => n.type === "string_literal")) {
    const value = literalValue(literal);
    const rawName = value === undefined ? undefined : assignedName(literal);
    if (value === undefined || !rawName || value.length < 4) continue;
    const name = normalizeName(rawName);
    if (isPlaceholder(value) || fixtureLike) continue;
    if (/^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$/.test(value) || /^\$\{/.test(value)) continue; // the NAME of an environment variable, a `${property}` reference
    const signing = isSigningSecretName(name);
    if (!signing && (!(isSensitiveName(name) && looksLikeSecret(value, name)) || isDemoLogin(text, literal.startIndex))) continue;
    if (signing && !looksLikeSecret(value, name) && value.length < 8) continue;
    add({
      ruleId: "hardcoded-secret",
      severity: "high",
      confidence: signing ? "high" : "medium",
      message: signing
        ? `\`${rawName}\` is a string written in the code (${redact(value)}) and is used to sign sessions or tokens. Anyone who reads the code can forge logins. Use a long random value from an environment variable (System.getenv("${name.toUpperCase()}")).`
        : `\`${rawName}\` is assigned a string that looks like a real credential (${redact(value)}). ${ROTATE}`,
      location: toLocation(literal, filePath),
      sourceSnippet: redact(value),
      sinkSnippet: (lines[literal.startPosition.row] ?? "").split(value).join("<redacted>").trim().slice(0, 160),
    });
  }
  return findings;
}
