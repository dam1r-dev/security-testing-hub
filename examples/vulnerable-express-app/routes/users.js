// VULNERABLE: SQL Injection (CWE-89) and reflected XSS (CWE-79).
module.exports = function registerUserRoutes(app, db) {
  app.get("/user/:id", (req, res) => {
    const id = req.params.id;
    const query = `SELECT * FROM users WHERE id = ${id}`; // SINK: string built with tainted input
    db.query(query, (err, rows) => {
      res.send(rows);
    });
  });

  app.get("/greet", (req, res) => {
    const name = req.query.name;
    res.send(`<h1>Hello ${name}</h1>`); // SINK: unescaped reflected input
  });

  // SAFE: parameterized query, not flagged.
  app.get("/user-safe/:id", (req, res) => {
    const id = req.params.id;
    db.query("SELECT * FROM users WHERE id = ?", [id], (err, rows) => {
      res.send(rows);
    });
  });
};
