// Intentionally vulnerable Express app, used to demonstrate/test the scanner.
// DO NOT deploy this anywhere reachable — every route here is broken on purpose.
const express = require("express");
const { exec } = require("child_process");
const fs = require("fs");
const db = require("./db"); // stub client with a .query(sql, cb) method

const app = express();
app.use(express.json());

require("./routes/users")(app, db);
require("./routes/search")(app, db);
require("./routes/files")(app, fs);
require("./routes/ping")(app, exec);
require("./routes/transfer")(app);

module.exports = app;
