const db = require("../../examples/vulnerable-express-app/db");
exports.findByOwner = (owner) => db.query("SELECT * FROM reports WHERE owner = '" + owner + "'");
