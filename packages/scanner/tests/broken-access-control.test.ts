import { scanSource } from "../src/index";
import { BrokenAccessControlAnalyzer } from "../src/analyzers/broken-access-control";

const analyzers = [new BrokenAccessControlAnalyzer()];

describe("BrokenAccessControlAnalyzer", () => {
  it("flags an /admin route with no auth check", () => {
    const source = `
      app.get("/admin/delete-user", (req, res) => {
        db.deleteUser(req.query.id);
        res.send("deleted");
      })
    `;
    const result = scanSource(source, "app.js", analyzers);
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]?.ruleId).toBe("broken-access-control");
  });

  it("flags a hidden/unguessable admin URL just the same (obscurity isn't access control)", () => {
    const source = `
      app.get("/internal/x7f2a9-console", (req, res) => {
        res.send(renderConsole());
      })
    `;
    const result = scanSource(source, "app.js", analyzers);
    expect(result.findings).toHaveLength(1);
  });

  it("does not flag when an auth check is present", () => {
    const source = `
      app.get("/admin/delete-user", requireAdmin, (req, res) => {
        db.deleteUser(req.query.id);
        res.send("deleted");
      })
    `;
    const result = scanSource(source, "app.js", analyzers);
    expect(result.findings).toHaveLength(0);
  });

  it("does not flag ordinary, non-privileged routes", () => {
    const source = `
      app.get("/products", (req, res) => {
        res.json(db.listProducts());
      })
    `;
    const result = scanSource(source, "app.js", analyzers);
    expect(result.findings).toHaveLength(0);
  });
});
