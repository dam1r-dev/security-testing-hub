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
  | "xxe";

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

export interface ScanSummary {
  filesScanned: number;
  findingsCount: number;
  results: ScanResult[];
  durationMs: number;
  /** Total findings hidden by `// security-hub-ignore` comments (reported, never silent). */
  suppressedCount?: number;
  /** Findings left out of the report because they are in files outside the requested scope (e.g. unchanged files). */
  filteredOutCount?: number;
}
