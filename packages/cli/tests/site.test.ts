import * as fs from "fs";
import * as path from "path";

const root = path.resolve(__dirname, "../../..");
const site = path.join(root, "site");
const html = fs.readFileSync(path.join(site, "index.html"), "utf8");

describe("GitHub Pages site (site/)", () => {
  it("every local image the page references exists (the three mascot states)", () => {
    const references = [...html.matchAll(/(?:src|href)="(assets\/[^"]+)"/g)].map((m) => m[1] as string);
    for (const state of ["safe", "warn", "danger"]) {
      expect(html).toContain(`assets/mascot-${state}.svg`);
    }
    for (const ref of new Set(references)) expect(fs.existsSync(path.join(site, ref))).toBe(true);
    for (const state of ["safe", "warn", "danger"]) {
      const svg = fs.readFileSync(path.join(site, "assets", `mascot-${state}.svg`), "utf8");
      expect(svg).toContain("<svg");
      expect(svg).toContain("aria-label"); // readable by screen readers
    }
  });

  it("makes no network request: a CSP forbids everything but itself, and no external script or image is used", () => {
    expect(html).toMatch(/Content-Security-Policy[^>]*default-src 'none'/);
    expect(html).not.toMatch(/<script[^>]+src=/i);
    expect(html).not.toMatch(/<(img|link)[^>]+(src|href)="https?:/i);
    expect(html).not.toMatch(/\b(fetch|XMLHttpRequest|WebSocket|sendBeacon)\b/);
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
