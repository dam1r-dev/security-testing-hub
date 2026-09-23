import { ParsedFile } from "../parsers/ast-parser";
import { findNodes, snippet, toLocation, SyntaxNode } from "../parsers/utils";
import { Finding } from "../types";
import { Analyzer } from "./base-analyzer";

const MULTER_CALLEE_PATTERN = /^multer$/;
const MIMETYPE_HINT = /\.mimetype\b|content-type/i;
const EXTENSION_CHECK_HINT = /originalname|extname|path\.extname|\.ext\b/i;

function isMulterCall(node: SyntaxNode): boolean {
  if (node.type !== "call_expression") return false;
  const callee = node.childForFieldName("function");
  return !!callee && callee.type === "identifier" && MULTER_CALLEE_PATTERN.test(callee.text);
}

function findFileFilterProperty(multerCall: SyntaxNode): SyntaxNode | undefined {
  const args = multerCall.childForFieldName("arguments");
  const optionsObject = args?.namedChild(0);
  if (!optionsObject || optionsObject.type !== "object") return undefined;
  return optionsObject.namedChildren.find(
    (prop) => prop.type === "pair" && prop.childForFieldName("key")?.text === "fileFilter",
  );
}

/**
 * Detects the classic "upload filter checks Content-Type only" bug: a
 * multer `fileFilter` that inspects `file.mimetype` (which comes straight
 * from the client-supplied `Content-Type` header/multipart field and can be
 * set to anything, e.g. `image/jpeg` on a `.php` file) without also checking
 * the actual file extension/name.
 */
export class InsecureFileUploadAnalyzer implements Analyzer {
  analyze(parsed: ParsedFile, filePath: string): Finding[] {
    const multerCalls = findNodes(parsed.tree.rootNode, isMulterCall);
    const findings: Finding[] = [];

    for (const call of multerCalls) {
      const fileFilterProp = findFileFilterProperty(call);
      if (!fileFilterProp) continue; // no fileFilter at all — different (broader) risk, not this specific bug
      const filterText = fileFilterProp.text;
      if (MIMETYPE_HINT.test(filterText) && !EXTENSION_CHECK_HINT.test(filterText)) {
        findings.push({
          ruleId: "insecure-file-upload",
          severity: "high",
          confidence: "medium",
          message:
            "This upload filter only checks file.mimetype (from the client-supplied Content-Type), not the " +
            "actual filename/extension. An attacker can upload a script (e.g. a .php web shell) with a spoofed " +
            "Content-Type like image/jpeg and bypass this check. Validate the file extension against an " +
            "allowlist and don't trust the client-provided MIME type.",
          location: toLocation(fileFilterProp, filePath),
          sourceSnippet: "multipart Content-Type (client-controlled)",
          sinkSnippet: snippet(fileFilterProp, parsed.sourceCode),
        });
      }
    }

    return findings;
  }
}
