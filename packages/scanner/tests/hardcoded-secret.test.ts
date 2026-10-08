import { execFileSync } from "child_process";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { scanPath, scanSource, toMarkdown, toSarifString, toHtml } from "../src/index";
import { HardcodedSecretAnalyzer } from "../src/analyzers/hardcoded-secret";
import { entropy, isPlaceholder, looksLikeSecret, redact } from "../src/secrets/detect";

// Token-shaped test values are assembled at run time so this file never contains a full
// provider-looking secret (which repository secret scanners would — rightly — flag).
const b64url = (value: object) => Buffer.from(JSON.stringify(value)).toString("base64url");
const TOKENS = {
  aws: "AKIA" + "Q7R2K9XM4WPD5LN8",
  github: "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8",
  stripeLive: "sk_" + "live_" + "4eC39HqLyjWDarjtT1zdp7dc",
  stripeTest: "sk_" + "test_" + "4eC39HqLyjWDarjtT1zdp7dc",
  anthropic: "sk-" + "ant-" + "api03-Zk3QpW7vLmN2xRtY9bHd5FgJ8cVn4XsA1uEi6oPq",
  openai: "sk-" + "proj-" + "T3bK9mXq2LzWv8RcYh5NfJd7PaUe4GsO1iVn6xCt",
  slack: "xox" + "b-" + "9283746510-Zk3QpW7vLmN2xRtY",
  privateKey: "-----BEGIN " + "RSA PRIVATE KEY-----",
  serviceRole: [b64url({ alg: "HS256", typ: "JWT" }), b64url({ role: "service_role", iss: "supabase" }), "c2lnbmF0dXJlLWJ5dGVzLWhlcmU"].join("."),
  anon: [b64url({ alg: "HS256", typ: "JWT" }), b64url({ role: "anon", iss: "supabase" }), "c2lnbmF0dXJlLWJ5dGVzLWhlcmU"].join("."),
  dbUrl: "postgres://" + "admin:" + "Sup3rS3cret" + "@db.prod-host.io:5432/shop",
};

const analyzers = [new HardcodedSecretAnalyzer()];
const scan = (source: string, file = "app.js") => scanSource(source, file, analyzers).findings;
const rules = (source: string) => scan(source).map((f) => f.ruleId);

describe("hardcoded-secret: known token formats", () => {
  it.each([
    ["AWS access key", TOKENS.aws],
    ["GitHub token", TOKENS.github],
    ["Stripe live key", TOKENS.stripeLive],
    ["Anthropic key", TOKENS.anthropic],
    ["OpenAI-style key", TOKENS.openai],
    ["Slack token", TOKENS.slack],
    ["private key", TOKENS.privateKey],
    ["Supabase service_role key", TOKENS.serviceRole],
    ["database URL with a password", TOKENS.dbUrl],
  ])("flags a %s", (_label, token) => {
    const findings = scan(`const client = connect("${token}");`);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.ruleId).toBe("hardcoded-secret");
    expect(findings[0]?.confidence).toBe("high");
  });

  it("gives the right severity: live keys critical, test keys low, AWS id high", () => {
    expect(scan(`x("${TOKENS.stripeLive}")`)[0]?.severity).toBe("critical");
    expect(scan(`x("${TOKENS.stripeTest}")`)[0]?.severity).toBe("low");
    expect(scan(`x("${TOKENS.aws}")`)[0]?.severity).toBe("high");
    expect(scan(`x("${TOKENS.serviceRole}")`)[0]?.severity).toBe("critical");
  });

  it("also catches a key sitting in a comment (it is still in the repository)", () => {
    expect(scan(`// old key: ${TOKENS.github}\nconst a = 1;`)).toHaveLength(1);
  });

  it("does not flag the public Supabase anon key, docs placeholders, or local/placeholder databases", () => {
    expect(scan(`createClient(url, "${TOKENS.anon}")`)).toHaveLength(0);
    expect(scan(`const k = "AKIAIOSFODNN7EXAMPLE";`)).toHaveLength(0);
    expect(scan(`const k = "${"sk_" + "live_" + "x".repeat(24)}";`)).toHaveLength(0); // assembled: a literal would trip push protection
    expect(scan(`const u = "postgres://postgres:postgres@localhost:5432/dev";`)).toHaveLength(0);
    expect(scan(`const u = "postgres://app:\${DB_PASSWORD}@db.prod-host.io/shop";`)).toHaveLength(0);
    expect(scan(`const u = "mongodb+srv://user:<password>@cluster0.mongodb.net/db";`)).toHaveLength(0);
  });

  it("reports the line of the secret", () => {
    const findings = scan(`const a = 1;\nconst b = 2;\nconst key = "${TOKENS.github}";\n`);
    expect(findings[0]?.location.startLine).toBe(3);
  });
});

describe("hardcoded-secret: never repeats a secret in a report", () => {
  it("redacts every value in the finding, JSON, markdown, SARIF and HTML output", () => {
    const source = Object.values(TOKENS)
      .filter((t) => t !== TOKENS.anon)
      .map((t, i) => `const k${i} = "${t}";`)
      .join("\n");
    const summary = {
      filesScanned: 1,
      findingsCount: 0,
      durationMs: 1,
      results: [scanSource(source, "app.js", analyzers)],
    };
    summary.findingsCount = summary.results[0]?.findings.length ?? 0;
    expect(summary.findingsCount).toBeGreaterThanOrEqual(9);

    const outputs = [JSON.stringify(summary), toMarkdown(summary), toSarifString(summary.results), toHtml(summary, "x")];
    for (const output of outputs) {
      for (const token of Object.values(TOKENS)) {
        // The only fragment of a secret allowed anywhere is its first few characters.
        expect(output).not.toContain(token);
        if (token.length > 20) expect(output).not.toContain(token.slice(0, 20));
      }
      expect(output).toContain("redacted");
    }
  });

  it("redact keeps only a recognisable head", () => {
    expect(redact("abcdefghijklmnopqrstuvwxyz")).toBe("abcd…[26 chars redacted]");
    expect(redact("short")).toBe("s…[5 chars redacted]");
  });
});

describe("hardcoded-secret: guessable signing secrets", () => {
  it("flags jwt.sign / jwt.verify with a string literal as the secret", () => {
    expect(rules(`const t = jwt.sign({ id: 1 }, "secret");`)).toEqual(["hardcoded-secret"]);
    expect(rules(`const p = jwt.verify(token, "my-jwt-key");`)).toEqual(["hardcoded-secret"]);
    expect(rules(`const t = jsonwebtoken.sign(p, 'abc123xyz');`)).toEqual(["hardcoded-secret"]);
  });

  it("does not flag a secret read from the environment, or a public key literal", () => {
    expect(rules(`jwt.sign({ id: 1 }, process.env.JWT_SECRET);`)).toEqual([]);
    expect(rules(`jwt.verify(token, "-----BEGIN PUBLIC KEY-----\\nMIIB...\\n-----END PUBLIC KEY-----");`)).toEqual([]);
    expect(rules(`jwt.sign({ id: 1 }, secret);`)).toEqual([]);
  });

  it("flags session({ secret: '...' }) including the famous example value", () => {
    expect(rules(`app.use(session({ secret: "keyboard cat", resave: false }));`)).toEqual(["hardcoded-secret"]);
  });

  it("flags signing-secret variables, and says when the value is a forgotten placeholder", () => {
    const findings = scan(`const JWT_SECRET = "your-secret-key";`);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.message).toContain("placeholder that was never replaced");
    expect(rules(`const sessionSecret = process.env.SESSION_SECRET || "dev-secret-123";`)).toEqual(["hardcoded-secret"]);
  });

  it("does not treat an unrelated `secret` property as a signing secret", () => {
    expect(rules(`const form = { secret: "x" };`)).toEqual([]);
    expect(rules(`const label = { secret: "Secret" };`)).toEqual([]);
  });
});

describe("hardcoded-secret: credentials by name", () => {
  it("flags a credential-looking value assigned to a sensitive name", () => {
    expect(rules(`const config = { password: "Adm1n!Pass#2024" };`)).toEqual(["hardcoded-secret"]);
    expect(rules(`const apiKey = "f83hD92kLm0Qp4Zx7Vb1";`)).toEqual(["hardcoded-secret"]);
    expect(rules(`client.accessToken = "q9Zr3Lk0Vb8Xw2Nm5Tc7";`)).toEqual(["hardcoded-secret"]);
    expect(rules(`class A { clientSecret = "Zx83!kLm02Qp94Vb"; }`)).toEqual(["hardcoded-secret"]);
  });

  it("does not flag labels, placeholders, sentences, env reads, or non-credential names", () => {
    expect(rules(`const t = { password: "Password", placeholder: "Enter your password" };`)).toEqual([]);
    expect(rules(`const password = "your-password-here";`)).toEqual([]);
    expect(rules(`const apiKey = process.env.API_KEY;`)).toEqual([]);
    expect(rules(`const token = req.headers.authorization;`)).toEqual([]);
    expect(rules(`const csrfToken = "a9F3kLm20Qp94Vb71Zx8";`)).toEqual([]);
    expect(rules(`const publicKey = "a9F3kLm20Qp94Vb71Zx8";`)).toEqual([]);
    expect(rules(`const message = "Your password must contain 8 characters";`)).toEqual([]);
    expect(rules(`const passwordField = "user_password_input";`)).toEqual([]);
    expect(rules(`fetch(url, { credentials: "same-origin", headers: { token: "bearer-token-here" } });`)).toEqual([]);
  });

  it("looksLikeSecret / isPlaceholder / entropy behave sensibly", () => {
    expect(looksLikeSecret("Adm1n!Pass#2024")).toBe(true);
    expect(looksLikeSecret("Password")).toBe(false);
    expect(looksLikeSecret("short")).toBe(false);
    expect(looksLikeSecret("https://example.com/path")).toBe(false);
    expect(isPlaceholder("your-api-key-here")).toBe(true);
    expect(isPlaceholder("${API_KEY}")).toBe(true);
    expect(entropy("aaaaaaaa")).toBe(0);
    expect(entropy("abcdefgh")).toBeCloseTo(3, 5);
  });
});

describe("hardcoded-secret: browser-exposed secrets", () => {
  it("flags secrets read through a public env prefix", () => {
    const findings = scan(`const c = createClient(url, process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY);`);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.message).toContain("browser-exposed");
    expect(rules(`const s = import.meta.env.VITE_STRIPE_SECRET_KEY;`)).toEqual(["hardcoded-secret"]);
    expect(rules(`const d = process.env.REACT_APP_DATABASE_URL;`)).toEqual(["hardcoded-secret"]);
  });

  it("does not flag variables that are meant to be public", () => {
    expect(rules(`process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY; process.env.NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY;`)).toEqual([]);
    expect(rules(`process.env.NEXT_PUBLIC_API_URL; process.env.STRIPE_SECRET_KEY;`)).toEqual([]);
  });

  it("does not flag a variable name that only appears in a comment", () => {
    expect(rules("// never read process.env.NEXT_PUBLIC_X_SECRET in the browser\n/** or import.meta.env.VITE_JWT_SECRET */\nconst a = 1;")).toEqual([]);
  });
});

describe("hardcoded-secret: suppression", () => {
  it("honours // security-hub-ignore", () => {
    const source = `// security-hub-ignore -- rotated, kept for the migration test\nconst k = "${TOKENS.github}";`;
    const result = scanSource(source, "app.js", analyzers);
    expect(result.findings).toHaveLength(0);
    expect(result.suppressed).toBe(1);
  });
});

describe(".env files", () => {
  let dir: string;
  const write = (rel: string, content: string) => {
    fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
    fs.writeFileSync(path.join(dir, rel), content);
  };
  const git = (...args: string[]) =>
    execFileSync("git", ["-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false", ...args], {
      cwd: dir,
      stdio: "pipe",
      encoding: "utf8",
    });
  const envFindings = () =>
    scanPath(dir).results.filter((r) => path.basename(r.file).startsWith(".env")).flatMap((r) => r.findings);
  const ENV = `# local settings\nPORT=3000\nSTRIPE_SECRET_KEY=${TOKENS.stripeLive}\nDATABASE_URL=${TOKENS.dbUrl}\nEMPTY_SECRET=\nNEXT_PUBLIC_NAME=shop\n`;

  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "sh-env-"));
    write("app.js", "const a = 1;\n");
  });
  afterEach(() => fs.rmSync(dir, { recursive: true, force: true }));

  it("a .env file committed to git is critical, one finding per secret, values redacted", () => {
    git("init", "-q");
    write(".env", ENV);
    git("add", "-A");
    git("commit", "-q", "-m", "oops");
    const findings = envFindings();
    expect(findings).toHaveLength(2);
    expect(findings.every((f) => f.severity === "critical" && f.ruleId === "hardcoded-secret")).toBe(true);
    expect(findings[0]?.message).toContain("committed to git");
    expect(findings[0]?.message).toContain("git rm --cached");
    expect(JSON.stringify(findings)).not.toContain(TOKENS.stripeLive);
    expect(JSON.stringify(findings)).not.toContain("Sup3rS3cret");
    expect(findings.map((f) => f.location.startLine)).toEqual([3, 4]);
  });

  it("an untracked .env that git does not ignore is a warning waiting to happen", () => {
    git("init", "-q");
    write(".env", ENV);
    const findings = envFindings();
    expect(findings).toHaveLength(2);
    expect(findings[0]?.severity).toBe("high");
    expect(findings[0]?.message).toContain("not ignored by git");
  });

  it("a .env file that .gitignore covers is the correct setup: no finding", () => {
    git("init", "-q");
    write(".gitignore", "node_modules\n.env\n");
    write(".env", ENV);
    expect(envFindings()).toHaveLength(0);
  });

  it("outside a git repository it reads .gitignore itself", () => {
    write(".env.local", ENV);
    expect(envFindings().length).toBeGreaterThan(0);
    expect(envFindings()[0]?.message).toContain("no git repository was found");
    write(".gitignore", ".env*\n");
    expect(envFindings()).toHaveLength(0);
  });

  it("skips .env.example and friends, empty values and placeholders", () => {
    write(".env.example", ENV);
    write(".env.production", "API_KEY=your-api-key-here\nSECRET_KEY=\nPASSWORD=changeme\n");
    expect(envFindings()).toHaveLength(0);
  });

  it("honours # security-hub-ignore and counts it", () => {
    write(".env", `# security-hub-ignore -- throwaway test key\nSTRIPE_SECRET_KEY=${TOKENS.stripeTest}\n`);
    const summary = scanPath(dir);
    expect(summary.results.flatMap((r) => r.findings)).toHaveLength(0);
    expect(summary.suppressedCount).toBe(1);
  });

  it("is reported as a scanned file and finds secrets in nested apps", () => {
    write("apps/web/.env", `OPENAI_API_KEY=${TOKENS.openai}\n`);
    const summary = scanPath(dir);
    expect(summary.filesScanned).toBe(2);
    expect(summary.findingsCount).toBe(1);
    expect(summary.results.find((r) => r.file.endsWith(".env"))?.findings[0]?.location.startLine).toBe(1);
  });
});
