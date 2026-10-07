// The "service layer": this is where the SQL is built. The route handlers that feed it
// user input live in routes/reports.js — a different file, so a scanner that only looks
// at one function at a time never connects the two.
const db = require("../db");

// VULNERABLE: `owner` is concatenated into the query text.
function findByOwner(owner) {
  return db.query("SELECT * FROM reports WHERE owner = '" + owner + "'");
}

// Safe: the value is a bound parameter.
function findByOwnerSafe(owner) {
  return db.query("SELECT * FROM reports WHERE owner = ?", [owner]);
}

// VULNERABLE through one more hop: search() -> runQuery(), which builds the SQL.
function runQuery(term) {
  return db.query(`SELECT * FROM reports WHERE title LIKE '%${term}%'`);
}
function search(term) {
  return runQuery(term);
}

module.exports = { findByOwner, findByOwnerSafe, search };
