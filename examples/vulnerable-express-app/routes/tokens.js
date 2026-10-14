// VULNERABLE: JSON Web Token misuse (CWE-347).
//  - POST /token  issues a token with no expiry: a stolen token works until the secret changes
//  - GET /me      verifies with the "none" algorithm allowed: an unsigned token is accepted
const jwt = require("jsonwebtoken");

module.exports = function registerTokenRoutes(app) {
  app.post("/token", (req, res) => {
    res.send({ token: jwt.sign({ id: req.session.userId, role: "user" }, process.env.JWT_SECRET) });
  });

  app.get("/me", (req, res) => {
    const claims = jwt.verify(req.headers.authorization, process.env.JWT_SECRET, { algorithms: ["HS256", "none"] });
    res.send(claims);
  });
};
