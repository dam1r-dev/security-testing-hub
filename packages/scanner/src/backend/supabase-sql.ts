import { Finding, Severity } from "../types";
import { QUALIFIED_NAME, QualifiedName, clause, columnNames, keyOf, parseQualified, splitSql, withoutDollarBodies } from "./sql";

/**
 * Supabase serves every table of an exposed schema (`public` by default) through an auto-generated REST
 * API that anyone holding the project's *public* anon key — it ships in the browser — can call. The only
 * thing standing between the internet and the data is Row Level Security: a table without RLS is a table
 * open to the world, and a policy that says `USING (true)` is the same thing with extra steps.
 *
 * This reads the SQL migrations as one timeline and reports the end state: what is still exposed after
 * every migration has run.
 */

export interface SqlFile {
  file: string;
  text: string;
}

export interface SupabaseSqlOptions {
  /** Schemas the API exposes (supabase/config.toml `[api] schemas`); default `["public"]`. */
  exposedSchemas?: string[];
}

interface Table {
  name: QualifiedName;
  file: string;
  line: number;
  columns: string[];
  rls: boolean;
  disabled?: { file: string; line: number };
  restricted: boolean;
}

interface Policy {
  name: string;
  table: QualifiedName;
  command: "all" | "select" | "insert" | "update" | "delete";
  roles: string[];
  using?: string;
  check?: string;
  file: string;
  line: number;
}

const NOT_USER_DATA = new Set(["spatial_ref_sys", "schema_migrations", "_prisma_migrations", "__drizzle_migrations", "supabase_migrations", "geography_columns", "geometry_columns"]);
const SENSITIVE_COLUMN = /email|phone|password|passwd|secret|token|api_?key|address|ssn|stripe|card|iban|birth|dob|private|salary|session/;
const SENSITIVE_TABLE = /user|profile|customer|order|payment|invoice|message|chat|account|subscription|private|secret|token|session|member|patient|document|file/;

const ROLE_ANON = new Set(["anon", "public"]);
const compact = (expr: string): string => expr.toLowerCase().replace(/\s+/g, "").replace(/[()]/g, "");

function isTrivial(expr: string | undefined): boolean {
  if (expr === undefined) return false;
  return /^(true|1=1|'true'|truetrue)$/.test(compact(expr));
}

function isSignedInOnly(expr: string | undefined): boolean {
  if (expr === undefined) return false;
  const e = compact(expr).replace(/select/g, "");
  return /^(auth\.uidisnotnull|auth\.role=.authenticated.|auth\.jwtisnotnull)$/.test(e);
}

const referencesUserMetadata = (expr: string | undefined): boolean => !!expr && /user_metadata|raw_user_meta_data/i.test(expr);

export function analyzeSupabaseSql(files: SqlFile[], options: SupabaseSqlOptions = {}): Map<string, Finding[]> {
  const exposed = new Set((options.exposedSchemas ?? ["public"]).map((s) => s.toLowerCase()));
  const tables = new Map<string, Table>();
  const policies = new Map<string, Policy>();
  const views: Array<{ name: QualifiedName; file: string; line: number; invoker: boolean; materialized: boolean; from: QualifiedName[] }> = [];
  const functions: Array<{ name: QualifiedName; file: string; line: number }> = [];
  const revokedViews = new Set<string>();
  let autoRls = false;
  let restrictAll = false;

  const ordered = [...files].sort((a, b) => a.file.localeCompare(b.file));
  for (const { file, text } of ordered) {
    for (const statement of splitSql(text)) {
      const s = statement.text;
      const line = statement.line;

      // `CREATE EVENT TRIGGER ... ensure_rls`: a project that switches RLS on for every new table itself.
      if (/event\s+trigger/i.test(s) && /row\s+level\s+security|rls/i.test(s)) autoRls = true;

      let m = new RegExp(String.raw`^create\s+(?:global\s+|local\s+)?(?:unlogged\s+)?table\s+(?:if\s+not\s+exists\s+)?${QUALIFIED_NAME}`, "i").exec(s);
      if (m) {
        if (/\bpartition\s+of\b/i.test(s)) continue;
        const name = parseQualified(m[1] as string);
        const existing = tables.get(keyOf(name));
        if (!existing) tables.set(keyOf(name), { name, file, line, columns: columnNames(s), rls: false, restricted: false });
        continue;
      }

      m = new RegExp(String.raw`^alter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?${QUALIFIED_NAME}\s+(.*)$`, "i").exec(s);
      if (m) {
        const name = parseQualified(m[1] as string);
        const table = tables.get(keyOf(name));
        const rest = m[2] as string;
        if (table) {
          if (/\benable\s+row\s+level\s+security\b/i.test(rest)) {
            table.rls = true;
            table.disabled = undefined;
          } else if (/\bdisable\s+row\s+level\s+security\b/i.test(rest)) {
            table.rls = false;
            table.disabled = { file, line };
          }
          const rename = new RegExp(String.raw`^rename\s+to\s+(${QUALIFIED_NAME.slice(1, -1)})`, "i").exec(rest);
          if (rename) {
            tables.delete(keyOf(name));
            table.name = { schema: name.schema, name: parseQualified(rename[1] as string).name };
            tables.set(keyOf(table.name), table);
          }
        }
        continue;
      }

      m = new RegExp(String.raw`^drop\s+table\s+(?:if\s+exists\s+)?(.+)$`, "i").exec(s);
      if (m) {
        for (const raw of (m[1] as string).replace(/\s+(cascade|restrict)\s*$/i, "").split(",")) tables.delete(keyOf(parseQualified(raw.trim())));
        continue;
      }

      m = new RegExp(String.raw`^create\s+policy\s+("[^"]+"|[A-Za-z_][A-Za-z0-9_$]*|'[^']+')\s+on\s+${QUALIFIED_NAME}\s*(.*)$`, "i").exec(s);
      if (m) {
        const rest = m[3] as string;
        const table = parseQualified(m[2] as string);
        const command = (/\bfor\s+(all|select|insert|update|delete)\b/i.exec(rest)?.[1]?.toLowerCase() ?? "all") as Policy["command"];
        const rolesText = /\bto\s+(.+?)(?=\s+using\b|\s+with\s+check\b|$)/i.exec(rest)?.[1];
        const roles = rolesText ? rolesText.split(",").map((r) => r.trim().replace(/^["']|["']$/g, "").toLowerCase()) : ["public"];
        const name = (m[1] as string).replace(/^["']|["']$/g, "");
        policies.set(`${keyOf(table)}::${name}`, {
          name,
          table,
          command,
          roles,
          using: clause(rest, /\busing\s*\(/i),
          check: clause(rest, /\bwith\s+check\s*\(/i),
          file,
          line,
        });
        continue;
      }

      m = new RegExp(String.raw`^drop\s+policy\s+(?:if\s+exists\s+)?("[^"]+"|[A-Za-z_][A-Za-z0-9_$]*)\s+on\s+${QUALIFIED_NAME}`, "i").exec(s);
      if (m) {
        policies.delete(`${keyOf(parseQualified(m[2] as string))}::${(m[1] as string).replace(/^"|"$/g, "")}`);
        continue;
      }

      m = new RegExp(String.raw`^alter\s+policy\s+("[^"]+"|[A-Za-z_][A-Za-z0-9_$]*)\s+on\s+${QUALIFIED_NAME}\s*(.*)$`, "i").exec(s);
      if (m) {
        const existing = policies.get(`${keyOf(parseQualified(m[2] as string))}::${(m[1] as string).replace(/^"|"$/g, "")}`);
        const rest = m[3] as string;
        if (existing) {
          const using = clause(rest, /\busing\s*\(/i);
          const check = clause(rest, /\bwith\s+check\s*\(/i);
          if (using !== undefined) existing.using = using;
          if (check !== undefined) existing.check = check;
        }
        continue;
      }

      m = new RegExp(String.raw`^create\s+(?:or\s+replace\s+)?(?:temp(?:orary)?\s+)?(materialized\s+)?view\s+${QUALIFIED_NAME}(.*)$`, "i").exec(s);
      if (m) {
        const rest = m[3] as string;
        const header = rest.split(/\bas\b/i)[0] ?? "";
        const from = [...rest.matchAll(new RegExp(String.raw`\b(?:from|join)\s+${QUALIFIED_NAME}`, "gi"))].map((x) => parseQualified(x[1] as string));
        views.push({
          name: parseQualified(m[2] as string),
          file,
          line,
          invoker: /security_invoker\s*=\s*(true|on|1)/i.test(header),
          materialized: !!m[1],
          from,
        });
        continue;
      }

      m = new RegExp(String.raw`^create\s+(?:or\s+replace\s+)?function\s+${QUALIFIED_NAME}\s*\(`, "i").exec(s);
      if (m) {
        const options_ = withoutDollarBodies(s);
        if (/\bsecurity\s+definer\b/i.test(options_) && !/\bset\s+search_path\b/i.test(options_) && !/\breturns\s+trigger\b/i.test(options_)) {
          functions.push({ name: parseQualified(m[1] as string), file, line });
        }
        continue;
      }

      m = /^revoke\s+.*?\s+on\s+(all\s+tables\s+in\s+schema\s+(\S+)|(?:table\s+)?(.+?))\s+from\s+(.+)$/i.exec(s);
      if (m) {
        const fromRoles = (m[4] as string).toLowerCase();
        const covers = /\b(anon|public)\b/.test(fromRoles) && (/\bauthenticated\b/.test(fromRoles) || /\bpublic\b/.test(fromRoles));
        if (!covers) continue;
        if (m[2]) {
          if (exposed.has((m[2] as string).replace(/"/g, "").toLowerCase())) restrictAll = true;
        } else {
          for (const raw of (m[3] as string).split(",")) {
            const key = keyOf(parseQualified(raw.trim()));
            const table = tables.get(key);
            if (table) table.restricted = true;
            revokedViews.add(key);
          }
        }
      }
    }
  }

  const byFile = new Map<string, Finding[]>();
  const add = (
    file: string,
    line: number,
    severity: Severity,
    confidence: Finding["confidence"],
    message: string,
    source: string,
    snippet: string,
  ): void => {
    const list = byFile.get(file) ?? [];
    list.push({
      ruleId: "supabase-rls",
      severity,
      confidence,
      message,
      location: { file, startLine: line, startColumn: 1, endLine: line, endColumn: snippet.length + 1 },
      sourceSnippet: source,
      sinkSnippet: snippet.length > 160 ? `${snippet.slice(0, 157)}...` : snippet,
    });
    byFile.set(file, list);
  };

  // 1. Tables the API exposes without Row Level Security.
  if (!autoRls && !restrictAll) {
    for (const table of tables.values()) {
      if (!exposed.has(table.name.schema) || table.rls || table.restricted || NOT_USER_DATA.has(table.name.name)) continue;
      const where = table.disabled ?? { file: table.file, line: table.line };
      const q = `${table.name.schema}.${table.name.name}`;
      add(
        where.file,
        where.line,
        "critical",
        table.disabled ? "high" : "medium",
        `Table ${q} is served by Supabase's auto-generated API but Row Level Security is ${table.disabled ? "switched OFF" : "never enabled"}. ` +
          `Anyone who has your project's anon key (it ships in the browser, so everyone does) can read, change and delete every row. ` +
          `Run: ALTER TABLE ${q} ENABLE ROW LEVEL SECURITY; and add policies that scope rows to their owner (e.g. USING (auth.uid() = user_id)).`,
        "row level security off",
        table.disabled ? `ALTER TABLE ${q} DISABLE ROW LEVEL SECURITY` : `CREATE TABLE ${q} (...)`,
      );
    }
  }

  // 2. Policies that let the wrong people in.
  for (const policy of policies.values()) {
    const isStorage = policy.table.schema === "storage" && policy.table.name === "objects";
    if (!isStorage && !exposed.has(policy.table.schema)) continue;
    const table = tables.get(keyOf(policy.table));
    const q = `${policy.table.schema}.${policy.table.name}`;
    const anonymous = policy.roles.some((r) => ROLE_ANON.has(r));
    const signedIn = policy.roles.includes("authenticated");
    const writes = policy.command === "all" || policy.command === "update" || policy.command === "delete";
    const snippet = `CREATE POLICY "${policy.name}" ON ${q} FOR ${policy.command.toUpperCase()}${policy.roles.length ? ` TO ${policy.roles.join(", ")}` : ""}`;
    const who = anonymous ? "anyone on the internet" : "any signed-in user (including anonymous sign-ins)";

    if (referencesUserMetadata(policy.using) || referencesUserMetadata(policy.check)) {
      add(
        policy.file,
        policy.line,
        "high",
        "high",
        `Policy "${policy.name}" on ${q} decides access from user_metadata. Users can edit their own user_metadata from the browser ` +
          `(supabase.auth.updateUser), so they can grant themselves any role the policy checks for. Use app_metadata (only the server can set it) ` +
          `or a roles table instead.`,
        "user_metadata in policy",
        snippet,
      );
    }

    if (isStorage) {
      const expr = (policy.check ?? policy.using ?? "").toLowerCase();
      const ownerChecked = /auth\.uid|owner/.test(expr);
      if (!ownerChecked && policy.command !== "select" && (anonymous || (signedIn && (writes || policy.command === "all")))) {
        add(
          policy.file,
          policy.line,
          anonymous ? "high" : "medium",
          "medium",
          `Policy "${policy.name}" on storage.objects lets ${who} ${policy.command === "insert" ? "upload to" : "overwrite or delete files in"} ` +
            `this bucket without checking who owns the file. Add an owner check, e.g. USING (bucket_id = 'x' AND (select auth.uid()) = owner_id::uuid) ` +
            `or a folder-per-user rule.`,
          "storage policy without owner check",
          snippet,
        );
      }
      continue;
    }

    if (writes && (anonymous || signedIn) && (isTrivial(policy.using) || (policy.command === "all" && isTrivial(policy.check) && policy.using === undefined))) {
      add(
        policy.file,
        policy.line,
        anonymous ? "critical" : "high",
        "high",
        `Policy "${policy.name}" on ${q} allows ${policy.command === "all" ? "every operation" : policy.command.toUpperCase()} for ${who} on EVERY row (USING true). ` +
          `That is the same as having no Row Level Security. Scope it to the row's owner: USING ((select auth.uid()) = user_id).`,
        "USING (true)",
        snippet,
      );
    } else if (policy.command === "insert" && anonymous && isTrivial(policy.check)) {
      add(
        policy.file,
        policy.line,
        "high",
        "high",
        `Policy "${policy.name}" on ${q} lets anyone on the internet insert rows with no check (WITH CHECK true): spam, junk data and abuse of ` +
          `your quota. Require a signed-in user or validate the row: WITH CHECK ((select auth.uid()) = user_id).`,
        "WITH CHECK (true)",
        snippet,
      );
    } else if (policy.command === "select" && anonymous && isTrivial(policy.using)) {
      const sensitive = SENSITIVE_TABLE.test(policy.table.name) || (table?.columns ?? []).some((c) => SENSITIVE_COLUMN.test(c));
      if (sensitive) {
        add(
          policy.file,
          policy.line,
          "high",
          "medium",
          `Policy "${policy.name}" on ${q} lets anyone on the internet read every row (USING true), and the table looks like it holds personal data ` +
            `(${[policy.table.name, ...(table?.columns ?? []).filter((c) => SENSITIVE_COLUMN.test(c))].slice(0, 4).join(", ")}). ` +
            `Restrict reads to the owner, or expose only the public columns through a view.`,
          "USING (true)",
          snippet,
        );
      }
    } else if (writes && isSignedInOnly(policy.using)) {
      add(
        policy.file,
        policy.line,
        "high",
        "medium",
        `Policy "${policy.name}" on ${q} only checks that the caller is signed in, for ${policy.command === "all" ? "every operation" : policy.command.toUpperCase()}: ` +
          `any signed-in user (anonymous sign-ins included) can modify or delete anyone else's rows. Compare the row's owner with the caller: ` +
          `USING ((select auth.uid()) = user_id).`,
        "auth.uid() IS NOT NULL",
        snippet,
      );
    }
  }

  // 3. Views run with their owner's rights and skip RLS unless they are security_invoker.
  for (const view of views) {
    if (!exposed.has(view.name.schema) || revokedViews.has(keyOf(view.name))) continue;
    const readsProtectedTable = view.from.some((t) => tables.get(keyOf(t))?.rls);
    if (view.materialized ? !readsProtectedTable : view.invoker || !readsProtectedTable) continue;
    const q = `${view.name.schema}.${view.name.name}`;
    add(
      view.file,
      view.line,
      "high",
      "medium",
      `${view.materialized ? "Materialized view" : "View"} ${q} reads tables that have Row Level Security, but ${view.materialized ? "materialized views cannot enforce it" : "runs with its owner's rights"}, ` +
        `so anyone who can call it through the API sees every row of those tables. ` +
        (view.materialized ? `Keep it out of the exposed schema or revoke access from anon/authenticated.` : `Create it WITH (security_invoker = true) (Postgres 15+), or revoke access from anon and authenticated.`),
      view.materialized ? "materialized view bypasses RLS" : "view without security_invoker",
      `CREATE VIEW ${q} ...`,
    );
  }

  // 4. SECURITY DEFINER functions with a mutable search_path.
  for (const fn of functions) {
    if (!exposed.has(fn.name.schema)) continue;
    const q = `${fn.name.schema}.${fn.name.name}`;
    add(
      fn.file,
      fn.line,
      "medium",
      "medium",
      `Function ${q} is SECURITY DEFINER (runs with its owner's rights, ignoring Row Level Security) and does not pin search_path. ` +
        `It is callable through the API as an RPC, and a caller who controls search_path can make it run their own objects. ` +
        `Add SET search_path = '' (and schema-qualify names inside), and REVOKE EXECUTE from anon if it is not meant to be public.`,
      "security definer without search_path",
      `CREATE FUNCTION ${q}(...) ... SECURITY DEFINER`,
    );
  }

  return byFile;
}
