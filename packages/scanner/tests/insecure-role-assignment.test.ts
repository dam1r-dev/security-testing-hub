import { scanSource } from "../src/index";
import { InsecureRoleAssignmentAnalyzer } from "../src/analyzers/insecure-role-assignment";

const analyzers = [new InsecureRoleAssignmentAnalyzer()];

describe("InsecureRoleAssignmentAnalyzer", () => {
  it("flags a role read from a cookie", () => {
    const source = `
      app.get("/dashboard", (req, res) => {
        if (req.cookies.Admin === "true") {
          return res.send(renderAdminDashboard());
        }
        res.send(renderUserDashboard());
      })
    `;
    const result = scanSource(source, "app.js", analyzers);
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]?.ruleId).toBe("insecure-role-assignment");
  });

  it("flags isAdmin read from the request body", () => {
    const source = `
      app.post("/register", (req, res) => {
        const isAdmin = req.body.isAdmin;
        createUser({ ...req.body, isAdmin });
      })
    `;
    const result = scanSource(source, "app.js", analyzers);
    expect(result.findings).toHaveLength(1);
  });

  it("does not flag unrelated request fields", () => {
    const source = `
      app.get("/greet", (req, res) => {
        res.send(\`Hello \${req.query.name}\`);
      })
    `;
    const result = scanSource(source, "app.js", analyzers);
    expect(result.findings).toHaveLength(0);
  });
});
