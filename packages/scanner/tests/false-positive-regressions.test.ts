import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { scanPath, scanSource } from "../src/index";
import { CsrfAnalyzer } from "../src/analyzers/csrf";
import { IdorAnalyzer } from "../src/analyzers/idor";
import { BrokenAccessControlAnalyzer } from "../src/analyzers/broken-access-control";

// Each case below is a false positive actually observed when running the
// scanner against real open-source projects (see docs/validation.md).

describe("CSRF: noise reduction", () => {
  const analyzers = [new CsrfAnalyzer()];

  it("reports ONE finding per file, not one per route", () => {
    const source = `
      router.post("/a", handlerA);
      router.post("/b", handlerB);
      router.put("/c", handlerC);
    `;
    const result = scanSource(source, "routes.js", analyzers);
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]?.message).toContain("3 state-changing routes");
  });

  it("does not flag webhook endpoints (signature-authenticated, not cookie-authenticated)", () => {
    const source = `
      export async function POST(req) {
        const sig = req.headers.get("stripe-signature");
        return Response.json({ received: true });
      }
    `;
    const result = scanSource(source, "app/api/webhooks/route.ts", analyzers);
    expect(result.findings).toHaveLength(0);
  });

  describe("bearer-token-only projects", () => {
    let dir: string;
    const writeProject = (deps: Record<string, string>) => {
      dir = fs.mkdtempSync(path.join(os.tmpdir(), "security-hub-bearer-"));
      fs.writeFileSync(path.join(dir, "package.json"), JSON.stringify({ dependencies: deps }));
      fs.writeFileSync(path.join(dir, "routes.js"), `router.post("/articles", createArticle);\n`);
    };
    afterEach(() => fs.rmSync(dir, { recursive: true, force: true }));

    it("skips CSRF when auth is JWT-in-header only", () => {
      writeProject({ express: "4", jsonwebtoken: "9" });
      expect(scanPath(dir, { analyzers }).findingsCount).toBe(0);
    });

    it("still flags it as soon as a cookie/session library is present", () => {
      writeProject({ express: "4", jsonwebtoken: "9", "express-session": "1" });
      expect(scanPath(dir, { analyzers }).findingsCount).toBe(1);
    });

    it("still flags it when there's no auth library information at all", () => {
      writeProject({ express: "4" });
      expect(scanPath(dir, { analyzers }).findingsCount).toBe(1);
    });
  });
});

describe("IDOR: id-param naming", () => {
  const analyzers = [new IdorAnalyzer()];

  it.each([":provider", ":video", ":guide", ":identifier"])("does not treat %s as an id param", (param) => {
    const source = `app.get("/thing/${param}", handler);`;
    expect(scanSource(source, "app.js", analyzers).findings).toHaveLength(0);
  });

  it.each([":id", ":userId", ":user_id", ":accountID"])("still treats %s as an id param", (param) => {
    const source = `app.get("/thing/${param}", handler);`;
    expect(scanSource(source, "app.js", analyzers).findings).toHaveLength(1);
  });
});

describe("Broken access control: recognised guards", () => {
  const analyzers = [new BrokenAccessControlAnalyzer()];

  it("accepts isLoggedIn / ensureAuthenticated style middleware", () => {
    for (const guard of ["isLoggedIn", "ensureAuthenticated", "requireLogin"]) {
      const source = `app.get("/admin/users", ${guard}, handler);`;
      expect(scanSource(source, "app.js", analyzers).findings).toHaveLength(0);
    }
  });

  it("no longer treats a plain /dashboard as a privileged area", () => {
    const source = `app.get("/dashboard", handler);`;
    expect(scanSource(source, "app.js", analyzers).findings).toHaveLength(0);
  });

  it("still flags an unguarded /admin route", () => {
    const source = `app.get("/admin/users", handler);`;
    expect(scanSource(source, "app.js", analyzers).findings).toHaveLength(1);
  });
});

describe("scanPath: files that aren't the project's own server code", () => {
  let dir: string;
  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "security-hub-skip-"));
    const loginBug = `if (!u) send("Invalid username"); else if (!ok) send("Invalid password"); // login\n`;
    const write = (rel: string) => {
      fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
      fs.writeFileSync(path.join(dir, rel), loginBug);
    };
    write("src/login.js"); // real code: must be scanned
    write("test/login_spec.js");
    write("tests/e2e/login.js");
    write("src/login.test.js");
    write("src/login.spec.ts");
    write("public/vendor/jquery.min.js");
    write("assets/vendor/lib.js");
    write("src/bundle.min.js");
  });
  afterEach(() => fs.rmSync(dir, { recursive: true, force: true }));

  it("scans only the real source file", () => {
    const summary = scanPath(dir);
    expect(summary.results.map((r) => path.relative(dir, r.file).replace(/\\/g, "/"))).toEqual(["src/login.js"]);
  });
});
