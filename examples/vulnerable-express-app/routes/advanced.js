// VULNERABLE: five more classes, each modelled on a real case from OWASP NodeGoat / dvna.
// All GET routes on purpose, so they don't also trip the anti-forgery rule.
module.exports = function registerAdvancedRoutes(app, db, serialize, libxmljs) {
  // Code injection (CWE-94): request data is evaluated as JavaScript.
  app.get("/calc", (req, res) => {
    const result = eval(req.query.expression);
    res.json({ result });
  });

  // Open redirect (CWE-601): the browser is sent wherever the URL says.
  app.get("/go", (req, res) => {
    res.redirect(req.query.url);
  });

  // NoSQL injection (CWE-943): a JSON body of {"username": {"$ne": null}} matches every user.
  app.get("/find-user", (req, res) => {
    db.users.findOne({ username: req.query.username }, (err, user) => res.json(user));
  });

  // Insecure deserialization (CWE-502): node-serialize revives and runs functions.
  app.get("/import-legacy", (req, res) => {
    const products = serialize.unserialize(req.query.data);
    res.json(products);
  });

  // XXE (CWE-611): external entities are switched on for user-supplied XML.
  app.get("/import-xml", (req, res) => {
    const doc = libxmljs.parseXmlString(req.query.xml, { noent: true, noblanks: true });
    res.json({ root: doc.root().name() });
  });
};
