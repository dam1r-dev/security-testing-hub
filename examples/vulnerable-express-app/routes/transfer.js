// VULNERABLE: Cross-Site Request Forgery (CWE-352) — state-changing route,
// no anti-forgery token verification anywhere in this file.
//
// (Deliberately not writing the four-letter acronym for this bug class in
// this file: the scanner's own detection rule for it treats that word
// appearing ANYWHERE in the file as evidence the bug is already fixed, so a
// comment describing the bug would silently suppress detecting the bug.)
module.exports = function registerTransferRoutes(app) {
  app.post("/transfer", (req, res) => {
    const { amount, to } = req.body;
    // ...move money using the authenticated session, no anti-forgery check...
    res.send({ status: "ok", amount, to });
  });
};
