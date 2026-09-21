// VULNERABLE: SQL Injection via knex-style .raw() call.
module.exports = function registerSearchRoutes(app, knex) {
  app.post("/search", (req, res) => {
    const term = req.body.term;
    knex.raw(`SELECT * FROM items WHERE name LIKE '%${term}%'`, (err, rows) => {
      res.send(rows);
    });
  });
};
