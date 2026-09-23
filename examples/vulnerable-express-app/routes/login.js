// VULNERABLE: Username Enumeration (CWE-203) — distinct error messages reveal
// whether the username exists before the password is even checked.
module.exports = function registerLoginRoutes(app, db, bcrypt) {
  app.post("/login", async (req, res) => {
    const user = await db.findUser(req.body.username);
    if (!user) {
      return res.status(401).send("Invalid username");
    }
    const ok = await bcrypt.compare(req.body.password, user.passwordHash);
    if (!ok) {
      return res.status(401).send("Invalid password");
    }
    res.send({ token: "signed-token-for-" + user.id });
  });
};
