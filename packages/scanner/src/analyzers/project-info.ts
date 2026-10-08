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
// Anything else that signals "this app has users and logins".
const OTHER_AUTH_DEPS =
  /^(passport(-.+)?|firebase|firebase-admin|@supabase\/supabase-js|auth0|@auth0\/.+|express-openid-connect|@okta\/.+|oauth2-server|bcrypt|bcryptjs|argon2|@node-rs\/argon2)$/;

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
          : has(BEARER_AUTH_DEPS)
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
