// VULNERABLE: OS Command Injection (CWE-78) via child_process.exec.
module.exports = function registerPingRoutes(app, exec) {
  app.post("/ping", (req, res) => {
    const host = req.body.host;
    exec(`ping -c 1 ${host}`, (err, stdout) => {
      res.send(stdout);
    });
  });
};
