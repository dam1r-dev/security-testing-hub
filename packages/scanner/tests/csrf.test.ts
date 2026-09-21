import { scanSource } from "../src/index";
import { CsrfAnalyzer } from "../src/analyzers/csrf";

const analyzers = [new CsrfAnalyzer()];

describe("CsrfAnalyzer", () => {
  it("flags a state-changing route with no CSRF protection in the file", () => {
    const source = `
      app.post("/transfer", (req, res) => {
        doTransfer(req.body.amount, req.body.to);
        res.send("ok");
      })
    `;
    const result = scanSource(source, "app.js", analyzers);
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]?.ruleId).toBe("csrf");
  });

  it("does not flag GET routes", () => {
    const source = `
      app.get("/balance", (req, res) => {
        res.send(getBalance());
      })
    `;
    const result = scanSource(source, "app.js", analyzers);
    expect(result.findings).toHaveLength(0);
  });

  it("does not flag files that already reference CSRF protection", () => {
    const source = `
      const csrf = require("csurf");
      app.use(csrf());
      app.post("/transfer", (req, res) => {
        doTransfer(req.body.amount, req.body.to);
        res.send("ok");
      })
    `;
    const result = scanSource(source, "app.js", analyzers);
    expect(result.findings).toHaveLength(0);
  });
});
