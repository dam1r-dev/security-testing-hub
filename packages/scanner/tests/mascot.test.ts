import { execFileSync } from "child_process";
import * as fs from "fs";
import * as path from "path";
import { MASCOT_IMAGE_BASE, MASCOT_NAME, mascotAlt, mascotDataUri, mascotImageUrl, mascotSay, toHtml, toMarkdown } from "../src/index";
import { Finding, ScanSummary } from "../src/types";

const root = path.resolve(__dirname, "../../..");

function summaryWith(severities: Finding["severity"][]): ScanSummary {
  const findings: Finding[] = severities.map((severity) => ({
    ruleId: "xss",
    severity,
    confidence: "high",
    message: "a message",
    location: { file: "app.js", startLine: 1, startColumn: 1, endLine: 1, endColumn: 1 },
    sourceSnippet: "",
    sinkSnippet: "",
  }));
  return { filesScanned: 1, findingsCount: findings.length, durationMs: 1, results: [{ file: "app.js", findings }] };
}

describe("Armo in the pull request comment", () => {
  it("sits beside the score, in the mood of the score, and the picture is one the website serves", () => {
    const calm = toMarkdown(summaryWith([]));
    const alarmed = toMarkdown(summaryWith(["critical", "critical", "critical", "critical", "critical"]));
    expect(calm).toContain(`<img src="${MASCOT_IMAGE_BASE}/mascot-safe.png"`);
    expect(alarmed).toContain(`<img src="${MASCOT_IMAGE_BASE}/mascot-danger.png"`);
    expect(alarmed).toContain(mascotSay("red"));
    expect(mascotImageUrl("yellow")).toBe(`${MASCOT_IMAGE_BASE}/mascot-warn.png`);
    for (const state of ["safe", "warn", "danger"]) {
      expect(fs.existsSync(path.join(root, "site", "assets", `mascot-${state}.png`))).toBe(true); // the URL points at a real file
    }
    expect(calm).toContain('width="88" align="right"');
  });

  it("can be left out, and the marker the bot finds its comment by stays first", () => {
    const plain = toMarkdown(summaryWith(["high"]), { mascot: false });
    expect(plain).not.toContain("<img");
    expect(plain).not.toContain(mascotSay("yellow"));
    expect(toMarkdown(summaryWith(["high"])).startsWith("<!-- security-testing-hub-report -->")).toBe(true);
  });
});

describe("mascot (Armo)", () => {
  it("is named Armo and has a different image and line for each mood", () => {
    expect(MASCOT_NAME).toBe("Armo");
    const colors = ["green", "yellow", "red"] as const;
    expect(new Set(colors.map(mascotDataUri)).size).toBe(3);
    expect(new Set(colors.map(mascotSay)).size).toBe(3);
    expect(new Set(colors.map(mascotAlt)).size).toBe(3);
    for (const color of colors) expect(mascotDataUri(color)).toMatch(/^data:image\/(svg\+xml|png|webp);base64,[A-Za-z0-9+/=]+$/);
  });

  it("the HTML report shows the mood that matches the score, embedded in the file (no external image)", () => {
    const calm = toHtml(summaryWith([]));
    const uneasy = toHtml(summaryWith(["high", "high", "high", "medium", "medium"])); // 100 - 38 = 62: the yellow band
    const alarmed = toHtml(summaryWith(["critical", "critical", "critical", "critical", "critical"]));
    expect(calm).toContain(`src="${mascotDataUri("green")}"`);
    expect(uneasy).toContain(`src="${mascotDataUri("yellow")}"`);
    expect(alarmed).toContain(`src="${mascotDataUri("red")}"`);
    expect(calm).toContain("Armo:");
    for (const html of [calm, uneasy, alarmed]) expect(html).not.toMatch(/<img[^>]+src="https?:/i);
  });

  it("the embedded images are the files in site/assets (run `npm run mascot` after changing the artwork)", () => {
    expect(() => execFileSync(process.execPath, [path.join(root, "scripts", "build-mascot.js"), "--check"], { stdio: "pipe" })).not.toThrow();
  });
});
