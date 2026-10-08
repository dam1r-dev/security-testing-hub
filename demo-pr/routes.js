const reports = require("./services/reports");
module.exports = (app) => {
  app.get("/reports", (req, res) => {
    res.json(reports.findByOwner(req.query.owner));
  });
};
