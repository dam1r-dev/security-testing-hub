// VULNERABLE: Broken Access Control (CWE-284/862) — no auth/role check at all.
// The URL being unpublished isn't protection; it's just obscurity.
module.exports = function registerAdminRoutes(app, db) {
  app.get("/admin/delete-user", (req, res) => {
    db.deleteUser(req.query.id);
    res.send("deleted");
  });
};
