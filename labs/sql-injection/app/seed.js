// Seeds a fresh SQLite database for the lab. Run once at image build time,
// so every container starts from the same known state.
const Database = require("better-sqlite3");
const path = require("path");
const fs = require("fs");

const DB_PATH = path.join(__dirname, "lab.db");
if (fs.existsSync(DB_PATH)) fs.unlinkSync(DB_PATH);

const db = new Database(DB_PATH);

db.exec(`
  CREATE TABLE products (
    id INTEGER PRIMARY KEY,
    category TEXT NOT NULL,
    name TEXT NOT NULL,
    price REAL NOT NULL,
    released INTEGER NOT NULL
  );
  CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    username TEXT NOT NULL,
    secret_token TEXT NOT NULL
  );
`);

const insertProduct = db.prepare(
  "INSERT INTO products (category, name, price, released) VALUES (?, ?, ?, ?)",
);
insertProduct.run("electronics", "Wireless Mouse", 19.99, 1);
insertProduct.run("electronics", "Mechanical Keyboard", 59.99, 1);
insertProduct.run("electronics", "Prototype Headset (unreleased)", 199.99, 0);
insertProduct.run("books", "Learn Node.js", 24.99, 1);
insertProduct.run("books", "Internal Style Guide (unreleased)", 0, 0);

const insertUser = db.prepare("INSERT INTO users (username, secret_token) VALUES (?, ?)");
insertUser.run("admin", "FLAG{sql_injection_via_category_param}");
insertUser.run("alice", "not-the-flag-alice-has-a-different-token");

db.close();
console.log("Seeded lab.db");
