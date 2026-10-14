import * as fs from "fs";
import * as path from "path";
import { Finding } from "../types";
import { FileWrite } from "./types";

/**
 * Supabase: one new migration that switches Row Level Security on for every table the scan found open.
 * With RLS on and no policy, Supabase's API denies the anon key and signed-in users everything; the server's
 * service-role key is not affected. Policies are the part only the owner of the app can write, so the migration
 * carries a commented example per table instead of guessing the rules.
 */

const TABLE_FINDING = /^Table (\S+) is served by Supabase's auto-generated API but Row Level Security is (?:never enabled|switched OFF)/;

export function tablesWithoutRls(findings: Finding[]): Array<{ table: string; file: string }> {
  const seen = new Set<string>();
  const tables: Array<{ table: string; file: string }> = [];
  for (const finding of findings) {
    const match = TABLE_FINDING.exec(finding.message);
    if (!match) continue;
    const table = match[1] as string;
    if (seen.has(table)) continue;
    seen.add(table);
    tables.push({ table, file: finding.location.file });
  }
  return tables;
}

function timestamp(now: Date): string {
  return now.toISOString().replace(/\D/g, "").slice(0, 14);
}

function quoteTable(table: string): string {
  return table
    .split(".")
    .map((part) => (/^[a-z_][a-z0-9_]*$/.test(part) ? part : `"${part.replace(/"/g, '""')}"`))
    .join(".");
}

/** The migration file to write next to the existing migrations. */
export function rlsMigration(tables: Array<{ table: string; file: string }>, now: Date = new Date()): FileWrite | undefined {
  const first = tables[0];
  if (!first) return undefined;
  const directory = path.dirname(first.file);
  const file = path.join(directory, `${timestamp(now)}_enable_row_level_security.sql`);
  const lines: string[] = [
    "-- Written by `security-hub fix`: turns Row Level Security on for tables the API exposes without it.",
    "-- With RLS on and no policy, the anon key and signed-in users can no longer read or write these tables through the",
    "-- API. Your server's service-role key is not affected. Add the policies your app needs BEFORE you deploy this.",
    "",
  ];
  for (const { table } of tables) {
    const quoted = quoteTable(table);
    lines.push(
      `ALTER TABLE ${quoted} ENABLE ROW LEVEL SECURITY;`,
      `-- Example policy (adjust the column that holds the owner):`,
      `-- CREATE POLICY "owner can read and write" ON ${quoted}`,
      `--   FOR ALL TO authenticated`,
      `--   USING ((select auth.uid()) = user_id)`,
      `--   WITH CHECK ((select auth.uid()) = user_id);`,
      "",
    );
  }
  const content = lines.join("\n");
  return { file, content, shown: content, created: !fs.existsSync(file), note: `a new migration that enables Row Level Security on ${tables.length} table(s)` };
}
