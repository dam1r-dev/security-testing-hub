// Web Worker entry: the page hands it the dropped files, it scans them off the main thread and posts the report back.
// Nothing here talks to the network except loading the scanner's own WebAssembly files from the same site.
import { initParser, languageForExtension, SupportedLanguage } from "./browser-parser";
import { scanFiles, MountedFile } from "./scan";

interface Scope {
  postMessage(message: unknown): void;
  onmessage: ((event: { data: unknown }) => void) | null;
  location: { href: string };
}
const scope = globalThis as unknown as Scope;

interface ScanRequest {
  type: "scan";
  files: MountedFile[];
  includeTests?: boolean;
}

async function fetchBytes(name: string): Promise<Uint8Array> {
  const response = await fetch(new URL(name, scope.location.href));
  if (!response.ok) throw new Error(`Could not load ${name} (${response.status}).`);
  return new Uint8Array(await response.arrayBuffer());
}

const GRAMMAR_FILES: Record<SupportedLanguage, string> = {
  javascript: "tree-sitter-javascript.wasm",
  typescript: "tree-sitter-typescript.wasm",
  tsx: "tree-sitter-tsx.wasm",
};

/** The runtime and only the grammars the dropped project needs: a plain JavaScript project never downloads the 1.4 MB TypeScript ones. */
async function load(files: MountedFile[]): Promise<void> {
  const wanted = new Set<SupportedLanguage>();
  for (const file of files) {
    const dot = file.path.lastIndexOf(".");
    const language = dot === -1 ? undefined : languageForExtension(file.path.slice(dot));
    if (language) wanted.add(language);
  }
  const grammars = await Promise.all([...wanted].map(async (language) => [language, await fetchBytes(GRAMMAR_FILES[language])] as const));
  await initParser({ runtime: await fetchBytes("tree-sitter.wasm"), ...Object.fromEntries(grammars) });
}

scope.onmessage = (event) => {
  const request = event.data as ScanRequest;
  if (request?.type !== "scan") return;
  void (async () => {
    try {
      scope.postMessage({ type: "status", text: "loading" });
      await load(request.files);
      scope.postMessage({ type: "status", text: "scanning" });
      let lastPost = 0;
      const data = scanFiles(request.files, {
        includeTests: request.includeTests,
        onProgress: (done, total) => {
          const now = Date.now();
          if (now - lastPost < 100) return;
          lastPost = now;
          scope.postMessage({ type: "progress", done, total });
        },
      });
      scope.postMessage({ type: "result", data });
    } catch (err) {
      scope.postMessage({ type: "error", message: err instanceof Error ? err.message : String(err) });
    }
  })();
};
