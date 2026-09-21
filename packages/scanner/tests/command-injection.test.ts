import { scanSource } from "../src/index";
import { CommandInjectionAnalyzer } from "../src/analyzers/command-injection";

const analyzers = [new CommandInjectionAnalyzer()];

describe("CommandInjectionAnalyzer", () => {
  it("flags req.body used in exec()", () => {
    const source = `
      const { exec } = require("child_process");
      app.post("/ping", (req, res) => {
        const host = req.body.host;
        exec(\`ping -c 1 \${host}\`, (err, out) => res.send(out));
      })
    `;
    const result = scanSource(source, "app.js", analyzers);
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]?.severity).toBe("critical");
  });

  it("does not flag static commands", () => {
    const source = `
      const { exec } = require("child_process");
      app.get("/uptime", (req, res) => {
        exec("uptime", (err, out) => res.send(out));
      })
    `;
    const result = scanSource(source, "app.js", analyzers);
    expect(result.findings).toHaveLength(0);
  });
});
