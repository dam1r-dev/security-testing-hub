import { Severity } from "../types";

/**
 * Recognising secrets that were typed into the source. Two kinds of evidence:
 *  - *known formats*: tokens whose shape identifies the provider (AWS, GitHub, Stripe, ...);
 *    high confidence, because the shape alone is enough;
 *  - *context*: a string assigned to something named `password` / `apiKey` / `jwtSecret` ...
 *    that looks random rather than like a sentence, a path or a placeholder.
 *
 * Whatever is found must never be repeated in full in a report (reports end up in public pull
 * request comments): `redact` is the only way a secret is allowed to appear in output.
 */

export interface KnownSecret {
  id: string;
  label: string;
  severity: Severity;
  pattern: RegExp;
  /** Extra check on the matched text (placeholder / local-database / not-a-secret exclusions). */
  accept?: (match: RegExpExecArray) => boolean;
}

const PLACEHOLDER = /(example|your[_-]|xxxx|placeholder|dummy|fake|sample|changeme|replace[_-]?me|<[^>\s]+>|\*{3,}|\.{3,}|0{8,}|1234567890|abcdefgh)/i;
const LOCAL_HOST = /^(localhost|127\.0\.0\.1|0\.0\.0\.0|\[?::1\]?|host\.docker\.internal)$/i;

export function isPlaceholder(value: string): boolean {
  return PLACEHOLDER.test(value) || /^\$\{.*\}$/.test(value) || /^%\w+%$/.test(value);
}

/** Shannon entropy in bits per character. Random tokens sit around 4+, English words around 2.5-3. */
export function entropy(value: string): number {
  if (value.length === 0) return 0;
  const counts = new Map<string, number>();
  for (const ch of value) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  let bits = 0;
  for (const count of counts.values()) {
    const p = count / value.length;
    bits -= p * Math.log2(p);
  }
  return bits;
}

/** bcrypt / argon2 / scrypt / pbkdf2 / crypt() hashes: what a seed file or a user table is SUPPOSED to hold. */
export function isPasswordHash(value: string): boolean {
  return /^\$(?:2[abxy]|argon2(?:id|i|d)|scrypt|pbkdf2[-\w]*|[156y7])\$/.test(value) || /^pbkdf2_sha\d+\$/.test(value);
}

/** A value that plausibly IS a credential (as opposed to a label, a sentence, a path or a placeholder). */
export function looksLikeSecret(value: string, normalizedName?: string): boolean {
  if (value.length < 8 || value.length > 512) return false;
  if (/\s/.test(value) || isPlaceholder(value)) return false;
  if (/^(https?:\/\/[^@\s]*$|\/|\.\.?\/|[a-z]:\\)/i.test(value)) return false; // URL without credentials / path
  // `same-origin`, `user_password_input`: lowercase words joined by - _ . are identifiers / option values, not secrets.
  if (/^[a-z]+(?:[-_.][a-z]+)+$/.test(value)) return false;
  // camelCase / PascalCase words (`incorrectPassword`, `resetPassword`, `MissingOldPassword`) are error codes and
  // enum values, and a password HASH (bcrypt, argon2, ...) is by design not a secret.
  // An error code names the thing it is about (`incorrectPassword`, `resetPassword`, `MissingOldPassword`),
  // while a passphrase like `IamUsedForTesting` does not: only the former is skipped.
  const keyword = normalizedName?.split("_").pop();
  const isWordsInCamelCase = /^[a-z]+(?:[A-Z][a-z0-9]*)+$/.test(value) || /^(?:[A-Z][a-z0-9]+){2,}$/.test(value);
  if (isWordsInCamelCase && keyword && value.toLowerCase().includes(keyword)) return false;
  if (isPasswordHash(value)) return false;
  const classes = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^A-Za-z0-9]/].filter((re) => re.test(value)).length;
  return classes >= 2 && entropy(value) >= 3.0;
}

/** `AKIA…(20 chars)`: enough to recognise which secret it is, never enough to use it. */
export function redact(secret: string): string {
  const head = secret.length > 12 ? secret.slice(0, 4) : secret.slice(0, 1);
  return `${head}…[${secret.length} chars redacted]`;
}

function decodeJwtPayload(token: string): Record<string, unknown> | undefined {
  try {
    const payload = token.split(".")[1] ?? "";
    const json = Buffer.from(payload.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8");
    const parsed: unknown = JSON.parse(json);
    return typeof parsed === "object" && parsed !== null ? (parsed as Record<string, unknown>) : undefined;
  } catch {
    return undefined;
  }
}

export const KNOWN_SECRETS: KnownSecret[] = [
  { id: "private-key", label: "private key", severity: "critical", pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----/g },
  { id: "aws-access-key", label: "AWS access key ID", severity: "high", pattern: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g, accept: (m) => !isPlaceholder(m[0]) },
  { id: "github-token", label: "GitHub token", severity: "critical", pattern: /\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{50,255})\b/g },
  { id: "stripe-live-key", label: "Stripe live secret key", severity: "critical", pattern: /\b[sr]k_live_[0-9a-zA-Z]{24,99}\b/g, accept: (m) => !isPlaceholder(m[0]) },
  { id: "stripe-test-key", label: "Stripe test secret key", severity: "low", pattern: /\b[sr]k_test_[0-9a-zA-Z]{24,99}\b/g, accept: (m) => !isPlaceholder(m[0]) },
  { id: "anthropic-key", label: "Anthropic API key", severity: "critical", pattern: /\bsk-ant-[A-Za-z0-9_-]{32,}\b/g, accept: (m) => !isPlaceholder(m[0]) },
  { id: "openai-key", label: "OpenAI-style API key", severity: "critical", pattern: /\bsk-(?!ant-)(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{32,}\b/g, accept: (m) => !isPlaceholder(m[0]) && entropy(m[0]) > 3.6 },
  { id: "slack-token", label: "Slack token", severity: "high", pattern: /\bxox[abprs]-[A-Za-z0-9-]{10,72}\b/g, accept: (m) => !isPlaceholder(m[0]) },
  { id: "slack-webhook", label: "Slack webhook URL", severity: "high", pattern: /https:\/\/hooks\.slack\.com\/services\/T[A-Za-z0-9]+\/B[A-Za-z0-9]+\/[A-Za-z0-9]{20,}/g, accept: (m) => !isPlaceholder(m[0]) },
  { id: "sendgrid-key", label: "SendGrid API key", severity: "high", pattern: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/g },
  { id: "npm-token", label: "npm access token", severity: "critical", pattern: /\bnpm_[A-Za-z0-9]{36}\b/g },
  { id: "telegram-bot-token", label: "Telegram bot token", severity: "high", pattern: /\b\d{8,10}:AA[A-Za-z0-9_-]{33}\b/g },
  {
    id: "supabase-service-role",
    label: "Supabase service_role key (full database access, bypasses row-level security)",
    severity: "critical",
    pattern: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g,
    // Only the service_role JWT is a secret; the anon key is meant to be public.
    accept: (m) => decodeJwtPayload(m[0])?.role === "service_role",
  },
  {
    id: "database-url",
    label: "database connection string with a password",
    severity: "high",
    pattern: /\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|rediss?|amqps?):\/\/([^\s:@/'"`]+):([^\s@/'"`]{3,})@([^\s/'"`:?]+)/g,
    accept: (m) => {
      const password = m[2] ?? "";
      const host = m[3] ?? "";
      // Local development databases and template placeholders aren't a leak.
      return !LOCAL_HOST.test(host) && !isPlaceholder(password) && !/^\$\{|^\{\{|^%/.test(password) && !isPlaceholder(host);
    },
  },
];

export interface KnownSecretMatch {
  secret: KnownSecret;
  index: number;
  text: string;
}

/** Finds every known-format secret in `text` (including inside comments: a leaked key in a comment is still leaked). */
export function findKnownSecrets(text: string): KnownSecretMatch[] {
  const found: KnownSecretMatch[] = [];
  for (const secret of KNOWN_SECRETS) {
    // `g` patterns keep state in lastIndex: always start fresh.
    const pattern = new RegExp(secret.pattern.source, secret.pattern.flags);
    let match: RegExpExecArray | null;
    while ((match = pattern.exec(text)) !== null) {
      if (match[0] === "") {
        pattern.lastIndex += 1;
        continue;
      }
      if (secret.accept && !secret.accept(match)) continue;
      found.push({ secret, index: match.index, text: match[0] });
    }
  }
  return found;
}

// ---- names ------------------------------------------------------------------

/** `apiKey` / `API-KEY` / `api_key` -> `api_key` */
export function normalizeName(name: string): string {
  return name
    .replace(/^.*\./, "")
    .replace(/([a-z0-9])([A-Z])/g, "$1_$2")
    .replace(/[-\s]+/g, "_")
    .toLowerCase();
}

const SENSITIVE_NAME =
  /(?:^|_)(?:secret|password|passwd|pwd|passphrase|api_?key|apikey|access_?key|secret_?key|private_?key|auth_?token|access_?token|refresh_?token|client_?secret|token)$/;
const NOT_A_CREDENTIAL = /(?:^|_)(?:public|publishable|csrf|xsrf|page|next|cache|session_?id|expires?|type|length)(?:_|$)/;

export function isSensitiveName(normalized: string): boolean {
  return SENSITIVE_NAME.test(normalized) && !NOT_A_CREDENTIAL.test(normalized);
}

/** Names of secrets that SIGN things: a guessable value lets anyone forge logins. */
const SIGNING_NAME = /(?:^|_)(?:jwt|session|cookie|signing|token|auth|app|access_?token|refresh_?token)_?secret(?:_?key)?$|^secret(?:_?key)?$|(?:^|_)signing_?key$/;

export function isSigningSecretName(normalized: string): boolean {
  return SIGNING_NAME.test(normalized);
}

/** `process.env.NEXT_PUBLIC_X_SECRET`: variables with these prefixes are copied into the browser bundle. */
const PUBLIC_ENV_PREFIX = /^(?:NEXT_PUBLIC|REACT_APP|VITE|EXPO_PUBLIC|GATSBY|NUXT_PUBLIC|PUBLIC)_/;
const SECRET_IN_NAME = /(?:SECRET|PRIVATE|SERVICE_ROLE|PASSWORD|DATABASE_URL)/;
const NOT_SECRET_IN_NAME = /(?:PUBLISHABLE|PUBLIC_KEY|PUBLIC_ID)/;

export function isPublicEnvSecretName(envName: string): boolean {
  return PUBLIC_ENV_PREFIX.test(envName) && SECRET_IN_NAME.test(envName) && !NOT_SECRET_IN_NAME.test(envName);
}
