import * as fs from "fs";
import * as path from "path";

// Token-in-header auth: the browser doesn't attach it automatically, so a
// forged cross-site request can't carry it (that's why CSRF doesn't apply).
const BEARER_AUTH_DEPS = /^(jsonwebtoken|express-jwt|passport-jwt|jose|@fastify\/jwt|fastify-jwt|koa-jwt)$/;
// Anything that puts a credential in a cookie the browser sends on its own.
const COOKIE_AUTH_DEPS =
  /^(express-session|cookie-session|cookie-parser|next-auth|@auth\/.+|iron-session|lucia|passport-local|connect-mongo|connect-redis|@supabase\/ssr|@supabase\/auth-helpers-nextjs|@clerk\/.+|better-auth|koa-session|@fastify\/session|@fastify\/cookie)$/;

const cache = new Map<string, boolean>();

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
const databaseKindCache = new Map<string, DatabaseKind>();

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
