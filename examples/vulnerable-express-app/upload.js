// VULNERABLE: Insecure File Upload (CWE-434) — filter trusts the client-supplied
// Content-Type/MIME type only, not the actual file extension.
const multer = require("multer");

const upload = multer({
  dest: "uploads/",
  fileFilter: function (req, file, cb) {
    if (file.mimetype.startsWith("image/")) {
      cb(null, true);
    } else {
      cb(new Error("Only images allowed"));
    }
  },
});

module.exports = upload;
