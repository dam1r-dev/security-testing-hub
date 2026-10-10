import * as http from "http";
import * as path from "path";
import { startUiServer, UiServer } from "../src/commands/ui";

const FIXTURE_APP = path.resolve(__dirname, "../../../examples/vulnerable-express-app");

interface Reply {
  status: number;
  headers: http.IncomingHttpHeaders;
  body: string;
}

function request(
  ui: UiServer,
  method: string,
  urlPath: string,
  options: { headers?: Record<string, string>; body?: unknown } = {},
): Promise<Reply> {
  return new Promise((resolve, reject) => {
    const req = http.request(
      { host: "127.0.0.1", port: ui.port, method, path: urlPath, headers: options.headers },
      (res) => {
        let body = "";
        res.setEncoding("utf8");
        res.on("data", (c) => (body += c));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, headers: res.headers, body }));
      },
    );
    req.on("error", reject);
    if (options.body !== undefined) req.write(JSON.stringify(options.body));
    req.end();
  });
}

describe("security-hub ui (local web interface)", () => {
  let ui: UiServer;
  const auth = (): Record<string, string> => ({ "x-security-hub-token": ui.token, "content-type": "application/json" });

  beforeAll(async () => {
    ui = await startUiServer({ port: 0, path: FIXTURE_APP });
  });
  afterAll(async () => {
    await new Promise((resolve) => ui.server.close(resolve));
  });

  it("binds to loopback only", () => {
    const address = ui.server.address() as { address: string };
    expect(address.address).toBe("127.0.0.1");
  });

  it("serves the page with a strict CSP and the run token", async () => {
    const reply = await request(ui, "GET", "/");
    expect(reply.status).toBe(200);
    expect(reply.body).toContain("Security Testing Hub");
    expect(reply.body).toContain(ui.token);
    const csp = String(reply.headers["content-security-policy"]);
    expect(csp).toMatch(/script-src 'nonce-[^']+'/);
    expect(csp).toContain("frame-ancestors 'none'");
    expect(csp).not.toContain("script-src 'unsafe-inline'");
    expect(csp).toContain("img-src data:"); // Armo is embedded, never loaded from anywhere
    expect(csp).not.toMatch(/img-src[^;]*https?:/);
    expect(reply.body).toContain('id="mascot"');
    expect(reply.body).toContain("data:image/");
  });

  it("refuses requests whose Host is not the loopback address (DNS rebinding)", async () => {
    const reply = await request(ui, "GET", "/", { headers: { host: "evil.example.com" } });
    expect(reply.status).toBe(403);
  });

  it("refuses API calls without the token", async () => {
    expect((await request(ui, "GET", "/api/browse")).status).toBe(403);
    const scan = await request(ui, "POST", "/api/scan", { body: { path: FIXTURE_APP } });
    expect(scan.status).toBe(403);
    const wrong = await request(ui, "POST", "/api/scan", {
      headers: { "x-security-hub-token": "x".repeat(ui.token.length) },
      body: { path: FIXTURE_APP },
    });
    expect(wrong.status).toBe(403);
  });

  it("refuses a scan POST coming from another origin even with the token", async () => {
    const reply = await request(ui, "POST", "/api/scan", {
      headers: { ...auth(), origin: "https://evil.example.com" },
      body: { path: FIXTURE_APP },
    });
    expect(reply.status).toBe(403);
  });

  it("scans a folder and returns score, findings and a downloadable HTML report", async () => {
    const reply = await request(ui, "POST", "/api/scan", { headers: auth(), body: { path: FIXTURE_APP } });
    expect(reply.status).toBe(200);
    const data = JSON.parse(reply.body);
    expect(data.score.color).toBe("red");
    expect(data.summary.findingsCount).toBeGreaterThan(10);
    expect(data.results.every((r: { findings: unknown[]; parseError?: string }) => r.findings.length > 0 || r.parseError)).toBe(true);
    expect(data.html).toMatch(/^<!DOCTYPE html>/);
  });

  it("returns a ready-to-paste AI prompt for every finding and one for all", async () => {
    const reply = await request(ui, "POST", "/api/scan", { headers: auth(), body: { path: FIXTURE_APP } });
    const data = JSON.parse(reply.body);
    const findings = data.results.flatMap((r: { findings: Array<{ fixPrompt: string; ruleId: string }> }) => r.findings);
    expect(findings.length).toBeGreaterThan(10);
    for (const f of findings) {
      expect(f.fixPrompt).toContain(`Rule: ${f.ruleId}`);
      expect(f.fixPrompt).toContain("How to fix:");
    }
    expect(data.allPrompt).toContain("## Issue 1");
    expect(data.allPrompt).toContain("Requirements for every fix:");
  });

  it("accepts a path pasted with quotes (Windows 'Copy as path')", async () => {
    const reply = await request(ui, "POST", "/api/scan", { headers: auth(), body: { path: `"${FIXTURE_APP}"` } });
    expect(reply.status).toBe(200);
  });

  it("reports a missing path and an empty path as errors, not crashes", async () => {
    const missing = await request(ui, "POST", "/api/scan", { headers: auth(), body: { path: path.join(FIXTURE_APP, "nope") } });
    expect(missing.status).toBe(404);
    expect(JSON.parse(missing.body).error).toContain("Path not found");
    const empty = await request(ui, "POST", "/api/scan", { headers: auth(), body: { path: " " } });
    expect(empty.status).toBe(400);
    const badJson = await request(ui, "POST", "/api/scan", { headers: auth(), body: undefined });
    expect(badJson.status).toBe(400);
  });

  it("lists sub-folders for the folder picker", async () => {
    const reply = await request(ui, "GET", `/api/browse?dir=${encodeURIComponent(path.dirname(FIXTURE_APP))}`, { headers: auth() });
    expect(reply.status).toBe(200);
    const data = JSON.parse(reply.body);
    const names = data.entries.map((e: { name: string }) => e.name);
    expect(names).toContain("vulnerable-express-app");
    expect(data.parent).toBeTruthy();
    expect(data.roots.length).toBeGreaterThan(0);
  });

  it("opens the nearest folder when browsing to a file path", async () => {
    const file = path.join(FIXTURE_APP, "app.js");
    const reply = await request(ui, "GET", `/api/browse?dir=${encodeURIComponent(file)}`, { headers: auth() });
    expect(JSON.parse(reply.body).dir).toBe(FIXTURE_APP);
  });

  it("returns 404 for unknown routes", async () => {
    expect((await request(ui, "GET", "/nope")).status).toBe(404);
    expect((await request(ui, "GET", "/api/nope", { headers: auth() })).status).toBe(404);
  });
});
