import { scanSource } from "../src/index";
import { InsecureFileUploadAnalyzer } from "../src/analyzers/insecure-file-upload";

const analyzers = [new InsecureFileUploadAnalyzer()];

describe("InsecureFileUploadAnalyzer", () => {
  it("flags a fileFilter that only checks file.mimetype", () => {
    const source = `
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
    `;
    const result = scanSource(source, "app.js", analyzers);
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]?.ruleId).toBe("insecure-file-upload");
  });

  it("does not flag a fileFilter that also checks the extension", () => {
    const source = `
      const upload = multer({
        dest: "uploads/",
        fileFilter: function (req, file, cb) {
          const ext = path.extname(file.originalname).toLowerCase();
          if (file.mimetype.startsWith("image/") && [".jpg", ".png"].includes(ext)) {
            cb(null, true);
          } else {
            cb(new Error("Only images allowed"));
          }
        },
      });
    `;
    const result = scanSource(source, "app.js", analyzers);
    expect(result.findings).toHaveLength(0);
  });

  it("does not flag multer calls without a fileFilter", () => {
    const source = `const upload = multer({ dest: "uploads/" });`;
    const result = scanSource(source, "app.js", analyzers);
    expect(result.findings).toHaveLength(0);
  });
});
