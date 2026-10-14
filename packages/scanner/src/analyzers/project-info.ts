import * as fs from "fs";
import * as path from "path";
import { FileCache } from "../file-cache";

// Token-in-header auth: the browser doesn't attach it automatically, so a
// forged cross-site request can't carry it (that's why CSRF doesn't apply).
const BEARER_AUTH_DEPS = /^(jsonwebtoken|express-jwt|passport-jwt|jose|@fastify\/jwt|fastify-jwt|koa-jwt)$/;
// Anything that puts a credential in a cookie the browser sends on its own.
const COOKIE_AUTH_DEPS =
  /^(express-session|cookie-session|cookie-parser|next-auth|@auth\/.+|iron-session|lucia|passport-local|connect-mongo|connect-redis|@supabase\/ssr|@supabase\/auth-helpers-nextjs|@clerk\/.+|better-auth|koa-session|@fastify\/session|@fastify\/cookie)$/;

const cache = new FileCache<boolean>();

function readDependencyNames(packageJsonPath: string): string[] | undefined {
  try {
    const pkg = JSON.parse(fs.readFileSync(packageJsonPath, "utf8"));
    return Object.keys({ ...pkg.dependencies, ...pkg.devDependencies });
  } catch {
    return undefined;
  }
}

/**
 * True when the nearest package.json shows token-in-header auth and NO
 * cookie/session auth — i.e. a pure bearer-token API, where CSRF isn't
 * exploitable. Deliberately conservative: any cookie/session library at all
 * keeps CSRF checking on, since one cookie-authenticated route is enough.
 */
export function isBearerOnlyProject(filePath: string): boolean {
  let dir = path.dirname(path.resolve(filePath));
  for (let depth = 0; depth < 10; depth++) {
    const candidate = path.join(dir, "package.json");
    if (fs.existsSync(candidate)) {
      const cached = cache.get(candidate);
      if (cached !== undefined) return cached;
      const deps = readDependencyNames(candidate);
      const result = !!deps && deps.some((d) => BEARER_AUTH_DEPS.test(d)) && !deps.some((d) => COOKIE_AUTH_DEPS.test(d));
      cache.set(candidate, result);
      return result;
    }
    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return false;
}

const MONGO_DEPS = /^(mongodb|mongoose|monk|mongojs|mongoskin|nedb|@typegoose\/typegoose|typegoose|@mikro-orm\/mongodb|mongodb-memory-server)$/;
const SQL_DEPS =
  /^(sequelize|sequelize-typescript|knex|pg|mysql|mysql2|sqlite3|better-sqlite3|mssql|oracledb|typeorm|@prisma\/client|prisma|drizzle-orm|objection|bookshelf|kysely|slonik|postgres)$/;

export type DatabaseKind = "mongo" | "sql" | "unknown";
const databaseKindCache = new FileCache<DatabaseKind>();

/**
 * Which kind of database the nearest package.json points at. "sql" means a
 * SQL driver/ORM and no MongoDB library — MongoDB-specific findings (operator
 * objects like {"$ne": null}) don't apply there. "unknown" (no package.json,
 * or no recognisable database library) keeps MongoDB checks on.
 */
export function databaseKind(filePath: string): DatabaseKind {
  let dir = path.dirname(path.resolve(filePath));
  for (let depth = 0; depth < 10; depth++) {
    const candidate = path.join(dir, "package.json");
    if (fs.existsSync(candidate)) {
      const cached = databaseKindCache.get(candidate);
      if (cached !== undefined) return cached;
      const deps = readDependencyNames(candidate) ?? [];
      const kind: DatabaseKind = deps.some((d) => MONGO_DEPS.test(d))
        ? "mongo"
        : deps.some((d) => SQL_DEPS.test(d))
          ? "sql"
          : "unknown";
      databaseKindCache.set(candidate, kind);
      return kind;
    }
    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return "unknown";
}

// Session cookies from these frameworks default to SameSite=Lax: a browser does not attach them
// to a cross-site POST, which is exactly what CSRF needs.
const LAX_COOKIE_AUTH_DEPS = /^(next-auth|@auth\/.+|@clerk\/.+|@supabase\/ssr|@supabase\/auth-helpers-nextjs|better-auth|iron-session|lucia)$/;
// Cookie/session middleware where the application chooses the cookie attributes itself.
const GENERIC_COOKIE_DEPS = /^(express-session|cookie-session|cookie-parser|koa-session|@fastify\/session|@fastify\/cookie|passport-local|csurf|cookies-next|cookie|connect-.+)$/;
// Client libraries that keep the user's token in the page (IndexedDB / localStorage) and send it in a header: the
// browser never attaches it to a cross-site request by itself, so CSRF cannot happen through them.
const TOKEN_CLIENT_DEPS = /^(firebase|firebase-admin|@supabase\/supabase-js)$/;
// Anything else that signals "this app has users and logins".
const OTHER_AUTH_DEPS =
  /^(passport(-.+)?|auth0|@auth0\/.+|express-openid-connect|@okta\/.+|oauth2-server|bcrypt|bcryptjs|argon2|@node-rs\/argon2)$/;

/**
 * - `cookies`: cookie/session middleware the app configures itself (CSRF can apply)
 * - `lax-cookies`: only frameworks whose session cookie is SameSite=Lax by default
 * - `bearer`: token-in-header auth only
 * - `none`: a package.json exists and shows no authentication library at all (a demo / public API)
 * - `unknown`: no package.json, or some other auth setup we can't classify: keep every check on
 */
export type AuthKind = "cookies" | "lax-cookies" | "bearer" | "none" | "unknown";
const authKindCache = new FileCache<AuthKind>();

export function authKind(filePath: string): AuthKind {
  let dir = path.dirname(path.resolve(filePath));
  for (let depth = 0; depth < 10; depth++) {
    const candidate = path.join(dir, "package.json");
    if (fs.existsSync(candidate)) {
      const cached = authKindCache.get(candidate);
      if (cached !== undefined) return cached;
      const deps = readDependencyNames(candidate) ?? [];
      const has = (re: RegExp): boolean => deps.some((d) => re.test(d));
      const kind: AuthKind = has(GENERIC_COOKIE_DEPS)
        ? "cookies"
        : has(LAX_COOKIE_AUTH_DEPS)
          ? "lax-cookies"
          : has(BEARER_AUTH_DEPS) || has(TOKEN_CLIENT_DEPS)
            ? has(OTHER_AUTH_DEPS)
              ? "unknown"
              : "bearer"
            : has(OTHER_AUTH_DEPS)
              ? "unknown"
              : "none";
      authKindCache.set(candidate, kind);
      return kind;
    }
    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return "unknown";
}

export interface SourceFacts {
  /** Some source file mentions CSRF/XSRF in code (middleware, a token check, ...). */
  csrf: boolean;
  /** The code reads the credential from the Authorization header. */
  authHeader: boolean;
  /** The code reads or sets cookies / sessions (a library merely being installed does not count). */
  cookieUse: boolean;
  /** Some source file limits how often a client may call (a rate limiter, a throttle, a lockout counter). */
  rateLimit: boolean;
}

// Rate limiting by library, in package.json.
const RATE_LIMIT_DEPS = /rate-?limit|limiter|throttl|slow-?down|@upstash\/ratelimit|arcjet|@nestjs\/throttler|bottleneck|express-brute|hono-rate-limiter/i;

/** Does package.json list a rate-limiting library? */
export function dependsOnRateLimiter(filePath: string): boolean {
  let dir = path.dirname(path.resolve(filePath));
  for (let depth = 0; depth < 10; depth++) {
    const candidate = path.join(dir, "package.json");
    if (fs.existsSync(candidate)) return (readDependencyNames(candidate) ?? []).some((d) => RATE_LIMIT_DEPS.test(d));
    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return false;
}

const SOURCE_EXT = /\.(?:[cm]?[jt]sx?)$/;
const SKIP_DIR = /^(?:node_modules|\.git|dist|build|\.next|out|coverage|vendor|\.turbo|__tests__|tests?|e2e|cypress)$/i;
const MAX_FACT_FILES = 800;
const MAX_FACT_BYTES = 300 * 1024;
const FACTS_TTL_MS = 20_000;
const factsCache = new Map<string, { at: number; facts: SourceFacts }>();

function stripComments(text: string): string {
  return text.replace(/\/\*[\s\S]*?\*\//g, " ").replace(/(^|[^:"'`\\])\/\/[^\n]*/g, "$1");
}

function projectRoot(filePath: string): string | undefined {
  let dir = path.dirname(path.resolve(filePath));
  for (let depth = 0; depth < 10; depth++) {
    if (fs.existsSync(path.join(dir, "package.json"))) return dir;
    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return undefined;
}

/**
 * What the project's own source code does about authentication and CSRF, read once per project (and again after
 * a short while, since `security-hub ui` keeps running while the code is edited). Dependencies alone mislead:
 * `cookie-session` can be installed and never used, and a CSRF middleware is usually registered in one entry file
 * while the routes live in a hundred others.
 */
export function sourceFacts(filePath: string): SourceFacts | undefined {
  const root = projectRoot(filePath);
  if (!root) return undefined;
  const cached = factsCache.get(root);
  if (cached && Date.now() - cached.at < FACTS_TTL_MS) return cached.facts;

  const facts: SourceFacts = { csrf: false, authHeader: false, cookieUse: false, rateLimit: false };
  let seen = 0;
  const walk = (dir: string): void => {
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      if (seen >= MAX_FACT_FILES) return;
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (!SKIP_DIR.test(entry.name)) walk(full);
      } else if (entry.isFile() && SOURCE_EXT.test(entry.name) && !/\.(?:test|spec)\./.test(entry.name)) {
        seen++;
        try {
          if (fs.statSync(full).size > MAX_FACT_BYTES) continue;
          const code = stripComments(fs.readFileSync(full, "utf8"));
          facts.csrf ||= /csrf|xsrf/i.test(code);
          facts.authHeader ||= /headers\??\.authorization|headers\[\s*['"]authorization['"]\s*\]|\.get\(\s*['"]authorization['"]\s*\)|\bBearer\b/i.test(code);
          facts.rateLimit ||= /rate[-_ ]?limit|ratelimit|limiter|throttl|slowDown|arcjet|failedAttempts|loginAttempts|lockout|too many (?:requests|attempts)|status\(\s*429\s*\)|status:\s*429/i.test(code);
          facts.cookieUse ||=/\b(?:req|request|ctx)\.(?:cookies|session)\b|\b(?:res|response)\.cookie\s*\(|\bcookies\s*\(\s*\)|\bcookieSession\s*\(|\bsession\s*\(\s*\{|\bsetCookie\b|\bcookieParser\s*\(/.test(code);
        } catch {
          // an unreadable file adds nothing
        }
      }
    }
  };
  walk(root);
  factsCache.set(root, { at: Date.now(), facts });
  return facts;
}
