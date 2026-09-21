import { scanSource } from "../src/index";
import { PathTraversalAnalyzer } from "../src/analyzers/path-traversal";

const analyzers = [new PathTraversalAnalyzer()];

describe("PathTraversalAnalyzer", () => {
  it("flags req.params used directly in fs.readFile", () => {
    const source = `
      const fs = require("fs");
      app.get("/files/:name", (req, res) => {
        const filename = req.params.name;
        fs.readFile(\`./uploads/\${filename}\`, (err, data) => res.send(data));
      })
    `;
    const result = scanSource(source, "app.js", analyzers);
    expect(result.findings).toHaveLength(1);
  });

  it("does not flag static paths", () => {
    const source = `
      const fs = require("fs");
      app.get("/logo", (req, res) => {
        fs.readFile("./assets/logo.png", (err, data) => res.send(data));
      })
    `;
    const result = scanSource(source, "app.js", analyzers);
    expect(result.findings).toHaveLength(0);
  });
});
