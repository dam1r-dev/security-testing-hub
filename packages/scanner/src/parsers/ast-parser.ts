import { collectGarbageToAvoidTreeSitterCorruption } from "./gc-workaround";
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

// node-tree-sitter's native binding throws "Invalid argument" when handed a
// plain string over ~32KB (it needs a contiguous fast-string buffer it can't
// get from V8 past that size). Feeding it a chunked reader callback instead
// sidesteps the limit, for files of any size. Real project files (especially
// generated code) regularly exceed 32KB, so this isn't an edge case.
//
// The chunked callback path is markedly less battle-tested than plain-string
// parsing, though: scanning many small files back-to-back through it produced
// occasional corrupted trees for files well past the first one in a process
// (reproducible, GC-timing-shaped). Plain-string parsing never showed that in
// extensive testing. So: use the safe, well-worn plain-string path by default,
// and only fall back to the chunked reader for the files that actually need it.
const SAFE_STRING_LIMIT = 30_000;
const PARSE_TIMEOUT_MICROS = 5_000_000;
const CHUNK_SIZE = 10_000;

function chunkedInput(sourceCode: string): (index: number) => string {
  return (index: number) => sourceCode.slice(index, index + CHUNK_SIZE);
}

/**
 * Parses a single source file into a Tree-sitter AST.
 * One Parser instance per call keeps this safe to run concurrently.
 */
export function parseSource(sourceCode: string, language: SupportedLanguage): ParsedFile {
  const parser = new Parser();
  parser.setLanguage(grammarFor(language));
  // Error recovery on hostile input is not linear: a megabyte of unbalanced quotes kept the native parser busy for
  // minutes. A file the parser cannot finish in a few seconds is not hand-written code worth waiting for.
  parser.setTimeoutMicros(PARSE_TIMEOUT_MICROS);
  const input = sourceCode.length > SAFE_STRING_LIMIT ? chunkedInput(sourceCode) : sourceCode;
  const tree = parser.parse(input);
  if (!tree) throw new Error(`parsing took longer than ${PARSE_TIMEOUT_MICROS / 1_000_000} seconds (a machine-generated or deliberately hostile file); it was skipped`);
  // See gc-workaround.ts: without this, a later parse() call in the same
  // process can silently return a corrupted tree. This applies to *every*
  // call site (scanPath's multi-file loop, but just as much a single test
  // file that calls scanSource() several times), so it belongs here, not
  // bolted onto individual callers.
  collectGarbageToAvoidTreeSitterCorruption();
  return { tree, language, sourceCode };
}

export function parseFile(filePath: string, sourceCode: string): ParsedFile | undefined {
  const extension = filePath.slice(filePath.lastIndexOf("."));
  const language = languageForExtension(extension);
  if (!language) return undefined;
  return parseSource(sourceCode, language);
}
