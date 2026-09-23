// VULNERABLE: SSRF (CWE-918) — server fetches a URL the client fully controls.
module.exports = function registerStockRoutes(app, axios) {
  app.post("/check-stock", (req, res) => {
    const stockApi = req.body.stockApi;
    axios.get(stockApi).then((r) => res.send(r.data));
  });
};
