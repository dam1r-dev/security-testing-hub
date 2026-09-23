import { scanSource } from "../src/index";
import { IdorAnalyzer } from "../src/analyzers/idor";

const analyzers = [new IdorAnalyzer()];

describe("IdorAnalyzer", () => {
  it("flags an id-param route with no ownership check", () => {
    const source = `
      app.get("/api/accounts/:accountId", (req, res) => {
        const account = db.findById(req.params.accountId);
        res.json(account);
      })
    `;
    const result = scanSource(source, "app.js", analyzers);
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]?.ruleId).toBe("idor");
  });

  it("does not flag when the handler checks req.user", () => {
    const source = `
      app.get("/api/accounts/:accountId", (req, res) => {
        const account = db.findById(req.params.accountId);
        if (account.ownerId !== req.user.id) return res.sendStatus(403);
        res.json(account);
      })
    `;
    const result = scanSource(source, "app.js", analyzers);
    expect(result.findings).toHaveLength(0);
  });

  it("does not flag routes without an id-like param", () => {
    const source = `
      app.get("/api/accounts", (req, res) => {
        res.json(db.findAll());
      })
    `;
    const result = scanSource(source, "app.js", analyzers);
    expect(result.findings).toHaveLength(0);
  });
});
