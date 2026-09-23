import { Finding, ScanResult, Severity, VulnerabilityType } from "../types";

const SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json";
const TOOL_NAME = "SecurityTestingHub";
const TOOL_VERSION = "0.1.0";
const TOOL_INFO_URI = "https://github.com/dam1r-dev/security-testing-hub";

const RULE_DESCRIPTIONS: Record<VulnerabilityType, { name: string; description: string; helpUri: string }> = {
  "sql-injection": {
    name: "SQL Injection",
    description: "User-controlled input flows into a SQL query without parameterization.",
    helpUri: "https://owasp.org/www-community/attacks/SQL_Injection",
  },
  xss: {
    name: "Cross-Site Scripting",
    description: "User-controlled input is written into an HTTP response without escaping.",
    helpUri: "https://owasp.org/www-community/attacks/xss/",
  },
  "command-injection": {
    name: "OS Command Injection",
    description: "User-controlled input flows into a shell command.",
    helpUri: "https://owasp.org/www-community/attacks/Command_Injection",
  },
  "path-traversal": {
    name: "Path Traversal",
    description: "User-controlled input is used to build a filesystem path.",
    helpUri: "https://owasp.org/www-community/attacks/Path_Traversal",
  },
  csrf: {
    name: "Cross-Site Request Forgery",
    description: "State-changing route with no detected CSRF protection.",
    helpUri: "https://owasp.org/www-community/attacks/csrf",
  },
  ssrf: {
    name: "Server-Side Request Forgery",
    description: "User-controlled input is used to build a URL that the server fetches.",
    helpUri: "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
  },
  idor: {
    name: "Insecure Direct Object Reference",
    description: "Route selects a record by an id-like param with no visible ownership check.",
    helpUri: "https://cwe.mitre.org/data/definitions/639.html",
  },
  "broken-access-control": {
    name: "Broken Access Control",
    description: "Privileged-looking route with no visible auth/role check.",
    helpUri: "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
  },
  "insecure-role-assignment": {
    name: "Insecure Role Assignment",
    description: "Role/permission is read directly from client-controlled input.",
    helpUri: "https://cwe.mitre.org/data/definitions/639.html",
  },
  "insecure-file-upload": {
    name: "Insecure File Upload",
    description: "Upload filter trusts the client-supplied Content-Type/MIME type only.",
    helpUri: "https://cwe.mitre.org/data/definitions/434.html",
  },
  "username-enumeration": {
    name: "Username Enumeration",
    description: "Login handler returns distinguishable errors for unknown users vs. wrong passwords.",
    helpUri: "https://cwe.mitre.org/data/definitions/203.html",
  },
};

function levelFor(severity: Severity): "error" | "warning" | "note" {
  if (severity === "critical" || severity === "high") return "error";
  if (severity === "medium") return "warning";
  return "note";
}

function toRelativeUri(filePath: string): string {
  return filePath.replace(/\\/g, "/").replace(/^\.?\//, "");
}

function findingToResult(finding: Finding) {
  return {
    ruleId: finding.ruleId,
    level: levelFor(finding.severity),
    message: { text: finding.message },
    properties: { confidence: finding.confidence },
    locations: [
      {
        physicalLocation: {
          artifactLocation: { uri: toRelativeUri(finding.location.file) },
          region: {
            startLine: finding.location.startLine,
            startColumn: finding.location.startColumn,
            endLine: finding.location.endLine,
            endColumn: finding.location.endColumn,
          },
        },
      },
    ],
  };
}

export function toSarif(results: ScanResult[]) {
  const usedRuleIds = new Set<VulnerabilityType>();
  const sarifResults = results.flatMap((r) =>
    r.findings.map((f) => {
      usedRuleIds.add(f.ruleId);
      return findingToResult(f);
    }),
  );

  const rules = [...usedRuleIds].map((ruleId) => {
    const info = RULE_DESCRIPTIONS[ruleId];
    return {
      id: ruleId,
      name: info.name.replace(/\s+/g, ""),
      shortDescription: { text: info.name },
      fullDescription: { text: info.description },
      helpUri: info.helpUri,
    };
  });

  return {
    $schema: SARIF_SCHEMA,
    version: "2.1.0" as const,
    runs: [
      {
        tool: {
          driver: {
            name: TOOL_NAME,
            informationUri: TOOL_INFO_URI,
            version: TOOL_VERSION,
            rules,
          },
        },
        results: sarifResults,
      },
    ],
  };
}

export function toSarifString(results: ScanResult[]): string {
  return JSON.stringify(toSarif(results), null, 2);
}
