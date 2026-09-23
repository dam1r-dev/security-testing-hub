import { scanSource } from "../src/index";
import { SsrfAnalyzer } from "../src/analyzers/ssrf";

const analyzers = [new SsrfAnalyzer()];

describe("SsrfAnalyzer", () => {
  it("flags req.query used directly as a fetch URL", () => {
    const source = `
      app.get("/proxy", async (req, res) => {
        const target = req.query.url;
        const result = await fetch(target);
        res.send(await result.text());
      })
    `;
    const result = scanSource(source, "app.js", analyzers);
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]?.ruleId).toBe("ssrf");
  });

  it("flags req.body.stockApi used with axios.get", () => {
    const source = `
      app.post("/check-stock", (req, res) => {
        const stockApi = req.body.stockApi;
        axios.get(stockApi).then((r) => res.send(r.data));
      })
    `;
    const result = scanSource(source, "app.js", analyzers);
    expect(result.findings).toHaveLength(1);
  });

  it("does not flag a static, hardcoded URL", () => {
    const source = `
      app.get("/health-upstream", async (req, res) => {
        const result = await fetch("https://status.example.com/health");
        res.send(await result.text());
      })
    `;
    const result = scanSource(source, "app.js", analyzers);
    expect(result.findings).toHaveLength(0);
  });
});
