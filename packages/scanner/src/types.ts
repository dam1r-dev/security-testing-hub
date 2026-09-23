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
  | "username-enumeration";

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
}

export interface ScanSummary {
  filesScanned: number;
  findingsCount: number;
  results: ScanResult[];
  durationMs: number;
}
