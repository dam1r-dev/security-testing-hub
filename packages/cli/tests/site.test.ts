import * as fs from "fs";
import * as path from "path";

const root = path.resolve(__dirname, "../../..");
const site = path.join(root, "site");
const html = fs.readFileSync(path.join(site, "index.html"), "utf8");

describe("GitHub Pages site (site/)", () => {
  it("every local image the page references exists (the three mascot states)", () => {
    const references = [...html.matchAll(/(?:src|href)="(assets\/[^"]+)"/g)].map((m) => m[1] as string);
    for (const state of ["safe", "warn", "danger"]) {
      expect(html).toContain(`assets/mascot-${state}.png`);
    }
    for (const ref of new Set(references)) expect(fs.existsSync(path.join(site, ref))).toBe(true);
    for (const state of ["safe", "warn", "danger"]) {
      const png = fs.readFileSync(path.join(site, "assets", `mascot-${state}.png`));
      expect(png.subarray(0, 8).toString("hex")).toBe("89504e470d0a1a0a"); // a real PNG
      expect(png.length).toBeLessThan(150 * 1024); // it is embedded in every report
    }
  });

  it("the hero image has a text alternative for screen readers", () => {
    expect(html).toMatch(/<img id="heroMascot"[^>]*alt="Armo/);
  });

  it("the page itself makes no network request: a CSP forbids everything but itself, and no external script or image is used", () => {
    expect(html).toMatch(/Content-Security-Policy[^>]*default-src 'none'/);
    expect(html).not.toMatch(/<script[^>]+src=/i);
    expect(html).not.toMatch(/<(img|link)[^>]+(src|href)="https?:/i);
    expect(html).not.toMatch(/\b(fetch|XMLHttpRequest|WebSocket|sendBeacon)\b/);
  });

  it("scans folders in a Web Worker from this site, and the policy allows exactly that", () => {
    expect(html).toMatch(/Content-Security-Policy[^>]*worker-src 'self'/);
    expect(html).toContain("new Worker('scanner/worker.js')");
    // the worker and its WebAssembly files are built by `npm run site:scanner` (not committed), in the Pages workflow
    const workflow = fs.readFileSync(path.join(root, ".github/workflows/pages.yml"), "utf8");
    expect(workflow).toContain("npm run site:scanner");
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const { WASM_FILES } = require(path.join(root, "scripts", "build-site-scanner.js"));
    expect((WASM_FILES as [string, string][]).map(([, name]) => name).sort()).toEqual(["tree-sitter-javascript.wasm", "tree-sitter-tsx.wasm", "tree-sitter-typescript.wasm", "tree-sitter.wasm"]);
    for (const [source] of WASM_FILES as [string, string][]) expect(fs.existsSync(source)).toBe(true);
  });

  it("shows findings with textContent only, never innerHTML (a report holds code from the scanned project)", () => {
    expect(html).not.toMatch(/innerHTML|insertAdjacentHTML|document\.write|outerHTML/);
  });

  it("lists as many rules as the scanner has", () => {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const { RULE_IDS } = require("security-hub-scanner");
    const listed = html.match(/var RULES = \[([\s\S]*?)\];/)?.[1] ?? "";
    expect(listed.split("',").length).toBe(RULE_IDS.length);
  });

  it("the Pages workflow is valid and stays off until PAGES_ENABLED is set", () => {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const yaml = require("js-yaml");
    const workflow = yaml.load(fs.readFileSync(path.join(root, ".github/workflows/pages.yml"), "utf8"));
    expect(workflow.jobs.deploy.if).toContain("PAGES_ENABLED");
    expect(workflow.permissions).toMatchObject({ pages: "write", "id-token": "write", contents: "read" });
  });
});

describe("the site's script policy", () => {
  it("allows exactly one inline script, by hash, and the hash is current (node scripts/update-site-csp.js)", () => {
    const csp = /Content-Security-Policy"[^>]*content="([^"]*)"/.exec(html)?.[1] ?? "";
    expect(csp).toMatch(/script-src 'sha256-[A-Za-z0-9+/=]+';/);
    // style-src may keep 'unsafe-inline' (inline CSS), script-src may not
    expect(csp).not.toMatch(/script-src[^;]*unsafe-inline/);
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const { execFileSync } = require("child_process");
    expect(() => execFileSync(process.execPath, [path.join(root, "scripts", "update-site-csp.js"), "--check"], { stdio: "pipe" })).not.toThrow();
  });
});
