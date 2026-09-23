// VULNERABLE: user role trusted straight from a client-controlled cookie (CWE-639/807).
module.exports = function registerDashboardRoutes(app) {
  app.get("/dashboard", (req, res) => {
    if (req.cookies.Admin === "true") {
      return res.send(renderAdminDashboard());
    }
    res.send(renderUserDashboard());
  });
};

function renderAdminDashboard() {
  return "<h1>Admin dashboard</h1>";
}

function renderUserDashboard() {
  return "<h1>User dashboard</h1>";
}
