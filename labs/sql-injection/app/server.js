// Deliberately vulnerable (by default) product-search endpoint, used as a
// hands-on SQL Injection lab. DO NOT deploy this anywhere reachable.
//
// Set SAFE_MODE=1 to switch to the parameterized-query fix, so the same
// exploit can be re-run against the patched version (see labs/sql-injection/e2e.js).
const express = require("express");
const Database = require("better-sqlite3");
const path = require("path");

const SAFE_MODE = process.env.SAFE_MODE === "1";
const db = new Database(path.join(__dirname, "lab.db"), { readonly: false });

const app = express();

app.get("/health", (req, res) => {
  res.json({ status: "ok", safeMode: SAFE_MODE });
});

app.get("/products", (req, res) => {
  const category = req.query.category ?? "";

  let rows;
  if (SAFE_MODE) {
    // FIX: parameterized query — the category value can never change the
    // query's structure, no matter what it contains.
    rows = db.prepare("SELECT id, name, price FROM products WHERE category = ? AND released = 1").all(category);
  } else {
    // VULNERABLE (CWE-89): the category value is concatenated directly into
    // the SQL text, so an attacker fully controls the query's structure.
    const sql = `SELECT id, name, price FROM products WHERE category = '${category}' AND released = 1`;
    rows = db.prepare(sql).all();
  }

  res.json(rows);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`SQL injection lab listening on :${PORT} (SAFE_MODE=${SAFE_MODE})`);
});
