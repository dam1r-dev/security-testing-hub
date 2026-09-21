import Parser = require("tree-sitter");
import JavaScript = require("tree-sitter-javascript");
// tree-sitter-typescript exposes two grammars: typescript and tsx
// eslint-disable-next-line @typescript-eslint/no-var-requires
const TypeScript = require("tree-sitter-typescript").typescript;
// eslint-disable-next-line @typescript-eslint/no-var-requires
const TSX = require("tree-sitter-typescript").tsx;

export type SupportedLanguage = "javascript" | "typescript" | "tsx";

const EXTENSION_TO_LANGUAGE: Record<string, SupportedLanguage> = {
  ".js": "javascript",
  ".jsx": "tsx",
  ".mjs": "javascript",
  ".cjs": "javascript",
  ".ts": "typescript",
  ".tsx": "tsx",
};

export function languageForExtension(extension: string): SupportedLanguage | undefined {
  return EXTENSION_TO_LANGUAGE[extension.toLowerCase()];
}

function grammarFor(language: SupportedLanguage) {
  switch (language) {
    case "javascript":
      return JavaScript;
    case "typescript":
      return TypeScript;
    case "tsx":
      return TSX;
  }
}

export interface ParsedFile {
  tree: Parser.Tree;
  language: SupportedLanguage;
  sourceCode: string;
}

/**
 * Parses a single source file into a Tree-sitter AST.
 * One Parser instance per call keeps this safe to run concurrently.
 */
export function parseSource(sourceCode: string, language: SupportedLanguage): ParsedFile {
  const parser = new Parser();
  parser.setLanguage(grammarFor(language));
  const tree = parser.parse(sourceCode);
  return { tree, language, sourceCode };
}

export function parseFile(filePath: string, sourceCode: string): ParsedFile | undefined {
  const extension = filePath.slice(filePath.lastIndexOf("."));
  const language = languageForExtension(extension);
  if (!language) return undefined;
  return parseSource(sourceCode, language);
}
