// Intentionally vulnerable Express app, used to demonstrate/test the scanner.
// DO NOT deploy this anywhere reachable — every route here is broken on purpose.
const express = require("express");
const cors = require("cors");
const { exec } = require("child_process");
const fs = require("fs");
const db = require("./db"); // stub client with .query/.findById/.findUser/.deleteUser methods
const axios = require("./axios"); // stub HTTP client
const bcrypt = require("./bcrypt"); // stub password hashing

const app = express();
app.use(express.json());
// VULNERABLE: every website may call this app with the visitor's cookies and read the answers (CWE-942).
app.use(cors({ origin: true, credentials: true }));
// VULNERABLE: serves the whole project folder (/app.js, /package.json, any .env) to the internet (CWE-538).
app.use(express.static(__dirname));

require("./routes/users")(app, db);
require("./routes/search")(app, db);
require("./routes/files")(app, fs);
require("./routes/ping")(app, exec);
require("./routes/transfer")(app);
require("./routes/accounts")(app, db);
require("./routes/admin")(app, db);
require("./routes/dashboard")(app);
require("./routes/stock")(app, axios);
require("./routes/login")(app, db, bcrypt);
require("./routes/reports")(app);
require("./routes/tokens")(app);
require("./routes/profile")(app);
require("./routes/advanced")(app, db, require("node-serialize"), require("libxmljs"));

module.exports = app;
