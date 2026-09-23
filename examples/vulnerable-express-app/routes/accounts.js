// VULNERABLE: IDOR (CWE-639) — no check that the account belongs to the caller.
module.exports = function registerAccountRoutes(app, db) {
  app.get("/api/accounts/:accountId", (req, res) => {
    const account = db.findById(req.params.accountId);
    res.json(account);
  });

  // SAFE: ownership is checked against the authenticated user, not flagged.
  app.get("/api/accounts-safe/:accountId", (req, res) => {
    const account = db.findById(req.params.accountId);
    if (!account || account.ownerId !== req.user.id) return res.sendStatus(403);
    res.json(account);
  });
};
