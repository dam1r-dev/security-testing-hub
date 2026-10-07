// VULNERABLE: SQL Injection (CWE-89) that crosses a file boundary.
// The handlers below only pass request data to the service layer; the vulnerable
// query is built in services/report-service.js.
const reportService = require("../services/report-service");

module.exports = function registerReportRoutes(app) {
  app.get("/reports", (req, res) => {
    res.json(reportService.findByOwner(req.query.owner));
  });

  app.get("/reports/search", (req, res) => {
    res.json(reportService.search(req.query.q));
  });

  app.get("/reports/mine", (req, res) => {
    res.json(reportService.findByOwnerSafe(req.query.owner));
  });
};
