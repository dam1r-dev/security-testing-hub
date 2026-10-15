// The browser's stand-in for src/parsers/ast-parser.ts. The build swaps it in (scripts/build-site-scanner.js), so every
// analyzer runs unchanged on web-tree-sitter (tree-sitter compiled to WebAssembly) instead of the native addon.
// Same exports, same behaviour; the one addition is initParser(), because WebAssembly has to be loaded before the first
// parse and that is asynchronous.
import Parser from "web-tree-sitter";
import type { ParsedFile, SupportedLanguage } from "../src/parsers/ast-parser";

export type { ParsedFile, SupportedLanguage };

export const JS_LANGUAGES: readonly SupportedLanguage[] = ["javascript", "typescript", "tsx"];

export interface WasmSources {
  /** tree-sitter.wasm from web-tree-sitter */
  runtime: Uint8Array;
  /** Each grammar is optional: the page loads only the ones the dropped project uses (the TypeScript ones are 1.4 MB each). */
  javascript?: Uint8Array;
  typescript?: Uint8Array;
  tsx?: Uint8Array;
  python?: Uint8Array;
  php?: Uint8Array;
}

const EXTENSION_TO_LANGUAGE: Record<string, SupportedLanguage> = {
  ".js": "javascript",
  ".jsx": "tsx",
  ".mjs": "javascript",
  ".cjs": "javascript",
  ".ts": "typescript",
  ".tsx": "tsx",
  ".py": "python",
  ".php": "php",
};

// Same limit as the native parser: real files parse in milliseconds, a hostile one never finishes.
const PARSE_TIMEOUT_MICROS = 20_000_000;

let languages: Partial<Record<SupportedLanguage, Parser.Language>> | undefined;

export async function initParser(sources: WasmSources): Promise<void> {
  await Parser.init({ wasmBinary: sources.runtime });
  languages = {};
  for (const language of ["javascript", "typescript", "tsx", "python", "php"] as const) {
    const wasm = sources[language];
    if (wasm) languages[language] = await Parser.Language.load(wasm);
  }
}

export function languageForExtension(extension: string): SupportedLanguage | undefined {
  return EXTENSION_TO_LANGUAGE[extension.toLowerCase()];
}

export function parseSource(sourceCode: string, language: SupportedLanguage): ParsedFile {
  if (!languages) throw new Error("The parser is not loaded yet (call initParser first).");
  const parser = new Parser();
  const started = Date.now();
  try {
    const grammar = languages[language];
    if (!grammar) throw new Error(`The ${language} grammar was not loaded.`);
    parser.setLanguage(grammar);
    parser.setTimeoutMicros(PARSE_TIMEOUT_MICROS);
    const tree = parser.parse(sourceCode);
    return { tree: tree as unknown as ParsedFile["tree"], language, sourceCode };
  } catch (err) {
    if (Date.now() - started >= PARSE_TIMEOUT_MICROS / 1000 - 500) {
      throw new Error(`parsing took longer than ${PARSE_TIMEOUT_MICROS / 1_000_000} seconds (a machine-generated or deliberately hostile file); it was skipped`);
    }
    throw err;
  } finally {
    parser.delete(); // WebAssembly memory is not garbage collected; the tree it made stays valid
  }
}

export function parseFile(filePath: string, sourceCode: string): ParsedFile | undefined {
  const extension = filePath.slice(filePath.lastIndexOf("."));
  const language = languageForExtension(extension);
  if (!language) return undefined;
  return parseSource(sourceCode, language);
}
