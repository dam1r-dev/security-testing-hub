export type VulnerabilityType =
  | "sql-injection"
  | "xss"
  | "command-injection"
  | "path-traversal"
  | "csrf"
  | "ssrf"
  | "idor"
  | "broken-access-control"
  | "insecure-role-assignment"
  | "insecure-file-upload"
  | "username-enumeration"
  | "code-injection"
  | "open-redirect"
  | "nosql-injection"
  | "insecure-deserialization"
  | "xxe"
  | "hardcoded-secret"
  | "supabase-rls"
  | "supabase-auth"
  | "firebase-rules"
  | "insecure-cors"
  | "insecure-jwt"
  | "missing-rate-limit"
  | "exposed-files"
  | "vulnerable-dependency"
  | "mass-assignment"
  | "prototype-pollution"
  | "webhook-signature"
  | "insecure-token-storage"
  | "debug-mode";

export type Severity = "critical" | "high" | "medium" | "low";

export interface SourceLocation {
  file: string;
  startLine: number;
  startColumn: number;
  endLine: number;
  endColumn: number;
}

export interface Finding {
  ruleId: VulnerabilityType;
  severity: Severity;
  message: string;
  location: SourceLocation;
  sourceSnippet: string;
  sinkSnippet: string;
  confidence: "high" | "medium" | "low";
}

export interface ScanResult {
  file: string;
  findings: Finding[];
  parseError?: string;
  /** Findings hidden by `// security-hub-ignore` comments in this file. */
  suppressed?: number;
}

/** What a scan did and did not look at: a clean report only means something for the code that was actually read. */
export interface Coverage {
  /** Source files (JavaScript, TypeScript, Python, PHP) that were analysed. */
  analyzed: number;
  /** Source files left out with a note: minified or bundled, a third-party library, over the size limit, unreadable. */
  skipped: number;
  /** Source files whose syntax the parser could not read completely (their results may be incomplete). */
  parseErrors: number;
  /** Files in languages the scanner has no rules for, by language ("Go": 120): their code was not checked at all. */
  unsupported: Record<string, number>;
}

export interface ScanSummary {
  filesScanned: number;
  /** Absent in summaries made before 0.8. */
  coverage?: Coverage;
  findingsCount: number;
  results: ScanResult[];
  durationMs: number;
  /** Total findings hidden by `// security-hub-ignore` comments (reported, never silent). */
  suppressedCount?: number;
  /** Findings left out of the report because they are in files outside the requested scope (e.g. unchanged files). */
  filteredOutCount?: number;
  /** Findings left out because the project's `.security-hub.json` disables their rule (reported, never silent). */
  disabledCount?: number;
  /** Findings the project's baseline already knows (see baseline.ts): they existed before and are not reported again. */
  baselinedCount?: number;
  /** Baseline entries that no longer match any finding: the problem was fixed, or its line was rewritten. */
  staleBaselineCount?: number;
}
