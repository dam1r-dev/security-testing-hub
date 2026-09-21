// VULNERABLE: Path Traversal (CWE-22) — no containment check on the resolved path.
module.exports = function registerFileRoutes(app, fs) {
  app.get("/files/:name", (req, res) => {
    const filename = req.params.name;
    fs.readFile(`./uploads/${filename}`, (err, data) => {
      res.send(data);
    });
  });
};
