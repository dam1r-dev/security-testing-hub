import * as path from "path";
import { Finding, ScanResult, Severity, VulnerabilityType } from "../types";

const SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json";
const TOOL_NAME = "SecurityTestingHub";
// Read at runtime so the SARIF `version` can never drift from the published package.json
// (dist/output/ and src/output/ both sit two levels below the package root).
// eslint-disable-next-line @typescript-eslint/no-var-requires, @typescript-eslint/no-require-imports
const TOOL_VERSION: string = require("../../package.json").version;
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
  "code-injection": {
    name: "Code Injection",
    description: "User-controlled input is executed as code (eval, Function, vm, ...).",
    helpUri: "https://cwe.mitre.org/data/definitions/94.html",
  },
  "open-redirect": {
    name: "Open Redirect",
    description: "User-controlled input decides where the server redirects the browser.",
    helpUri: "https://cwe.mitre.org/data/definitions/601.html",
  },
  "nosql-injection": {
    name: "NoSQL Injection",
    description: "User-controlled input reaches a NoSQL query as an operator object or server-side JavaScript ($where).",
    helpUri: "https://cwe.mitre.org/data/definitions/943.html",
  },
  "insecure-deserialization": {
    name: "Insecure Deserialization",
    description: "User-controlled input is deserialized with a library that can execute code.",
    helpUri: "https://cwe.mitre.org/data/definitions/502.html",
  },
  xxe: {
    name: "XML External Entity",
    description: "User-controlled XML is parsed with external entity expansion enabled.",
    helpUri: "https://cwe.mitre.org/data/definitions/611.html",
  },
  "hardcoded-secret": {
    name: "Hard-coded Secret",
    description: "A password, API key, token or signing secret is written into the source code or a committed .env file.",
    helpUri: "https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password",
  },
  "supabase-rls": {
    name: "Supabase Row Level Security",
    description: "A Supabase table is exposed through the API without Row Level Security, or a policy lets anyone in.",
    helpUri: "https://supabase.com/docs/guides/database/postgres/row-level-security",
  },
  "supabase-auth": {
    name: "Supabase Auth Misuse",
    description: "Server code trusts an unverified Supabase session, or decides access from user-editable user_metadata.",
    helpUri: "https://supabase.com/docs/guides/auth/server-side/nextjs",
  },
  "firebase-rules": {
    name: "Firebase Security Rules",
    description: "Firestore, Cloud Storage or Realtime Database rules let anyone (or any signed-in user) read or write other people's data.",
    helpUri: "https://firebase.google.com/docs/rules/insecure-rules",
  },
  "insecure-cors": {
    name: "Insecure CORS",
    description: "CORS accepts any origin (or reflects the request's Origin) while allowing credentials, so any website can act as the logged-in user.",
    helpUri: "https://portswigger.net/web-security/cors",
  },
  "insecure-jwt": {
    name: "Insecure JSON Web Token use",
    description: "Tokens are accepted without a signature (alg none), never expire, or are decoded without being verified.",
    helpUri: "https://cwe.mitre.org/data/definitions/347.html",
  },
  "missing-rate-limit": {
    name: "Missing rate limiting on sign-in",
    description: "A login or code-check endpoint checks the credential itself and nothing limits the number of attempts.",
    helpUri: "https://cwe.mitre.org/data/definitions/307.html",
  },
  "mass-assignment": {
    name: "Mass assignment",
    description: "The whole request body is written to the database, so the caller can set fields such as role, isAdmin or price.",
    helpUri: "https://cwe.mitre.org/data/definitions/915.html",
  },
  "prototype-pollution": {
    name: "Prototype pollution",
    description: "Request data is deep-merged or used as a key of a nested assignment, so a body with __proto__ changes every object.",
    helpUri: "https://cwe.mitre.org/data/definitions/1321.html",
  },
  "webhook-signature": {
    name: "Webhook without signature verification",
    description: "A payment webhook handler acts on events without verifying the provider's signature, so anyone can forge them.",
    helpUri: "https://cwe.mitre.org/data/definitions/345.html",
  },
  "insecure-token-storage": {
    name: "Token kept in browser storage",
    description: "A login token is stored in localStorage, sessionStorage or a script-set cookie, where any script on the page can read it.",
    helpUri: "https://cwe.mitre.org/data/definitions/922.html",
  },
  "vulnerable-dependency": {
    name: "Vulnerable dependency",
    description: "A package your project depends on has a known security vulnerability (from npm's advisory database).",
    helpUri: "https://docs.npmjs.com/auditing-package-dependencies-for-security-vulnerabilities",
  },
  "exposed-files": {
    name: "Sensitive file in a public folder",
    description: "A secret, key, database dump or .git folder sits in a folder the web server serves to everyone.",
    helpUri: "https://cwe.mitre.org/data/definitions/538.html",
  },
};

function levelFor(severity: Severity): "error" | "warning" | "note" {
  if (severity === "critical" || severity === "high") return "error";
  if (severity === "medium") return "warning";
  return "note";
}

function toRelativeUri(filePath: string, relativeTo?: string): string {
  // GitHub code scanning matches `uri` against repository-relative paths, so an absolute
  // path (what a scan of an absolute folder produces) has to be made relative to the repo root.
  const normalized = relativeTo && path.isAbsolute(filePath) ? path.relative(relativeTo, filePath) : filePath;
  return normalized.replace(/\\/g, "/").replace(/^\.?\//, "");
}

function findingToResult(finding: Finding, relativeTo?: string) {
  return {
    ruleId: finding.ruleId,
    level: levelFor(finding.severity),
    message: { text: finding.message },
    properties: { confidence: finding.confidence },
    locations: [
      {
        physicalLocation: {
          artifactLocation: { uri: toRelativeUri(finding.location.file, relativeTo) },
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

export interface SarifOptions {
  /** Make absolute file paths relative to this folder (normally the repository root). */
  relativeTo?: string;
}

export function toSarif(results: ScanResult[], options: SarifOptions = {}) {
  const usedRuleIds = new Set<VulnerabilityType>();
  const sarifResults = results.flatMap((r) =>
    r.findings.map((f) => {
      usedRuleIds.add(f.ruleId);
      return findingToResult(f, options.relativeTo);
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

export function toSarifString(results: ScanResult[], options: SarifOptions = {}): string {
  return JSON.stringify(toSarif(results, options), null, 2);
}
