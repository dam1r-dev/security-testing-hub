// Minimal stand-in for a DB client, just so the analyzer sees a `.query()` call.
// Not a real database — this file has nothing to do with the vulnerability itself.
module.exports = {
  query(sql, paramsOrCallback, maybeCallback) {
    const callback = typeof paramsOrCallback === "function" ? paramsOrCallback : maybeCallback;
    if (callback) callback(null, []);
  },
};
