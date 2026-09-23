// Minimal stand-in for a DB client, just so the analyzer sees realistic calls.
// Not a real database — this file has nothing to do with the vulnerabilities themselves.
module.exports = {
  query(sql, paramsOrCallback, maybeCallback) {
    const callback = typeof paramsOrCallback === "function" ? paramsOrCallback : maybeCallback;
    if (callback) callback(null, []);
  },
  findById(id) {
    return { id, ownerId: "someone-else" };
  },
  findUser(username) {
    return Promise.resolve(username ? { id: username, passwordHash: "..." } : null);
  },
  deleteUser(id) {
    return true;
  },
};
