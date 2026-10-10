import { execFileSync } from "child_process";
import * as path from "path";
import { MASCOT_NAME, mascotAlt, mascotDataUri, mascotSay, toHtml } from "../src/index";
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
