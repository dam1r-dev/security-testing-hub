import { scanSource } from "../src/index";
import { SqlInjectionAnalyzer } from "../src/analyzers/sql-injection";

const analyzers = [new SqlInjectionAnalyzer()];

describe("SqlInjectionAnalyzer", () => {
  it("flags direct req.params interpolation into a template-literal query (plan Phase 2 example)", () => {
    const source = `
      app.get("/user/:id", (req, res) => {
        const id = req.params.id;
        const query = \`SELECT * FROM users WHERE id = \${id}\`;
        db.query(query);
      })
    `;
    const result = scanSource(source, "app.js", analyzers);
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]?.ruleId).toBe("sql-injection");
    expect(result.findings[0]?.severity).toBe("critical");
  });

  it("flags request data passed straight into db.query", () => {
    const source = `
      app.get("/user/:id", (req, res) => {
        db.query(\`SELECT * FROM users WHERE id = \${req.params.id}\`);
      })
    `;
    const result = scanSource(source, "app.js", analyzers);
    expect(result.findings).toHaveLength(1);
  });

  it("does not flag parameterized queries", () => {
    const source = `
      app.get("/user/:id", (req, res) => {
        const id = req.params.id;
        db.query("SELECT * FROM users WHERE id = ?", [id]);
      })
    `;
    const result = scanSource(source, "app.js", analyzers);
    expect(result.findings).toHaveLength(0);
  });

  it("does not flag queries with no tainted input", () => {
    const source = `
      app.get("/health", (req, res) => {
        db.query("SELECT 1");
      })
    `;
    const result = scanSource(source, "app.js", analyzers);
    expect(result.findings).toHaveLength(0);
  });

  it("does NOT follow taint through a helper function call (documented intra-procedural limitation)", () => {
    const source = `
      function sanitize(input) { return input; }
      app.get("/user/:id", (req, res) => {
        const id = sanitize(req.params.id);
        db.query(\`SELECT * FROM users WHERE id = \${id}\`);
      })
    `;
    // This mirrors the plan's "NOT FOUND (yet)" example — the analyzer only
    // tracks taint within a single function body, so it misses this flow.
    // We assert the current (known) behavior so a future inter-procedural
    // upgrade changes this test deliberately, not silently.
    const result = scanSource(source, "app.js", analyzers);
    expect(result.findings).toHaveLength(0);
  });

  it("flags SQL injection via knex.raw", () => {
    const source = `
      app.post("/search", (req, res) => {
        const term = req.body.term;
        knex.raw(\`SELECT * FROM items WHERE name LIKE '%\${term}%'\`);
      })
    `;
    const result = scanSource(source, "app.js", analyzers);
    expect(result.findings).toHaveLength(1);
  });
});
