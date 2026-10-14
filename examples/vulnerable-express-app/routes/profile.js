// VULNERABLE: jwt.decode() used as if it verified the token (CWE-347). decode only reads the payload,
// so anyone can send a token they wrote themselves with role "admin". This file never calls jwt.verify().
const jwt = require("jsonwebtoken");

module.exports = function registerProfileRoutes(app) {
  app.get("/profile", (req, res) => {
    const claims = jwt.decode(req.headers.authorization);
    res.send({ isAdmin: claims.role === "admin" });
  });
};
