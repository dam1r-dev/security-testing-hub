// VULNERABLE: CSRF (CWE-352) — state-changing route, no CSRF token verification anywhere in this file.
module.exports = function registerTransferRoutes(app) {
  app.post("/transfer", (req, res) => {
    const { amount, to } = req.body;
    // ...move money using the authenticated session, no CSRF check...
    res.send({ status: "ok", amount, to });
  });
};
