// Intentionally vulnerable Express app, used to demonstrate/test the scanner.
// DO NOT deploy this anywhere reachable — every route here is broken on purpose.
const express = require("express");
const { exec } = require("child_process");
const fs = require("fs");
const db = require("./db"); // stub client with .query/.findById/.findUser/.deleteUser methods
const axios = require("./axios"); // stub HTTP client
const bcrypt = require("./bcrypt"); // stub password hashing

const app = express();
app.use(express.json());

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

module.exports = app;
