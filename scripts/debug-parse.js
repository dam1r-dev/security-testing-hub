// Temporary diagnostic script for a CI-only native-binding issue.
// Runs the exact same scanSource() call path as the failing/passing Jest
// tests, but directly under plain `node` (no Jest), to determine whether
// the bug is Jest-specific (module/vm-context isolation) or a genuine
// native tree-sitter binding problem on this runner.
const { scanSource, defaultAnalyzers } = require("../packages/scanner/dist/index");

console.log("process.versions:", JSON.stringify(process.versions, null, 2));

const cases = [
  {
    name: "sql-injection-like (PASSES in Jest)",
    source: `
      app.get("/user/:id", (req, res) => {
        const id = req.params.id;
        const query = \`SELECT * FROM users WHERE id = \${id}\`;
        db.query(query);
      })
    `,
  },
  {
    name: "xss-like (FAILS in Jest)",
    source: `
      app.get("/greet", (req, res) => {
        const name = req.query.name;
        res.send(\`<h1>Hello \${name}</h1>\`);
      })
    `,
  },
  {
    name: "command-injection-like (FAILS in Jest)",
    source: `
      const { exec } = require("child_process");
      app.post("/ping", (req, res) => {
        const host = req.body.host;
        exec(\`ping -c 1 \${host}\`, (err, out) => res.send(out));
      })
    `,
  },
];

for (const { name, source } of cases) {
  console.log(`\n=== ${name} ===`);
  try {
    const result = scanSource(source, "app.js", defaultAnalyzers());
    console.log("parseError:", result.parseError);
    console.log("findings:", result.findings.length);
  } catch (err) {
    console.log("THREW:", err.stack);
  }
}
