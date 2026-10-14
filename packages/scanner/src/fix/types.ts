import { Finding } from "../types";

/** Replace `[start, end)` of a file's text. Offsets are into the ORIGINAL text. */
export interface TextEdit {
  file: string;
  start: number;
  end: number;
  text: string;
  /** What this edit does, in one line, for the report ("parameterized 2 value(s) in the query"). */
  note: string;
  /** A secret this edit removes from the text: a preview must never print it. */
  secret?: string;
}

/** A whole file to create or append to. `shown` is what a preview prints (a secret is never printed). */
export interface FileWrite {
  file: string;
  /** Full new content of the file. */
  content: string;
  /** Preview text: the same file with anything secret masked. */
  shown: string;
  /** True when the file did not exist. */
  created: boolean;
  note: string;
}

export interface SkippedFinding {
  finding: Finding;
  reason: string;
}

export interface FixPlan {
  /** Original text of every file an edit or an append touches (for previews and backups). */
  originals: Record<string, string>;
  edits: TextEdit[];
  writes: FileWrite[];
  /** Things to do by hand after the fix (rotate a secret, add policies, set an environment variable). */
  todo: string[];
  /** Findings that have a fixer but could not be fixed safely, with the reason. */
  skipped: SkippedFinding[];
  /** Findings of kinds that have no automatic fix. */
  manual: number;
}

export interface FixOptions {
  /** Only fix these rules (default: every rule that has a fixer). */
  only?: string[];
}

/** Rules that have an automatic fixer. */
export const FIXABLE_RULES = ["sql-injection", "insecure-jwt", "hardcoded-secret", "insecure-cors", "supabase-rls"] as const;
