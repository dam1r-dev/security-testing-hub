import { scanSource } from "../src/index";
import { UsernameEnumerationAnalyzer } from "../src/analyzers/username-enumeration";

const analyzers = [new UsernameEnumerationAnalyzer()];

describe("UsernameEnumerationAnalyzer", () => {
  it("flags distinct 'unknown user' vs 'wrong password' messages in a login handler", () => {
    const source = `
      app.post("/login", async (req, res) => {
        const user = await db.findUser(req.body.username);
        if (!user) {
          return res.status(401).send("Invalid username");
        }
        const ok = await bcrypt.compare(req.body.password, user.passwordHash);
        if (!ok) {
          return res.status(401).send("Invalid password");
        }
        res.send({ token: issueToken(user) });
      })
    `;
    const result = scanSource(source, "app.js", analyzers);
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]?.ruleId).toBe("username-enumeration");
  });

  it("does not flag a single, identical error message for both cases", () => {
    const source = `
      app.post("/login", async (req, res) => {
        const user = await db.findUser(req.body.username);
        const ok = user && (await bcrypt.compare(req.body.password, user.passwordHash));
        if (!ok) {
          return res.status(401).send("Invalid username or password");
        }
        res.send({ token: issueToken(user) });
      })
    `;
    const result = scanSource(source, "app.js", analyzers);
    expect(result.findings).toHaveLength(0);
  });

  it("does not flag unrelated functions", () => {
    const source = `
      function formatUserName(user) {
        return user.firstName + " " + user.lastName;
      }
    `;
    const result = scanSource(source, "app.js", analyzers);
    expect(result.findings).toHaveLength(0);
  });
});
