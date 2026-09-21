import { scanSource } from "../src/index";
import { XssAnalyzer } from "../src/analyzers/xss";

const analyzers = [new XssAnalyzer()];

describe("XssAnalyzer", () => {
  it("flags req.query reflected directly into res.send", () => {
    const source = `
      app.get("/greet", (req, res) => {
        const name = req.query.name;
        res.send(\`<h1>Hello \${name}</h1>\`);
      })
    `;
    const result = scanSource(source, "app.js", analyzers);
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]?.ruleId).toBe("xss");
  });

  it("does not flag static responses", () => {
    const source = `
      app.get("/health", (req, res) => {
        res.send("OK");
      })
    `;
    const result = scanSource(source, "app.js", analyzers);
    expect(result.findings).toHaveLength(0);
  });
});
