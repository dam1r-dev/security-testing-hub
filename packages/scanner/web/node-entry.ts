// Entry of the Node build of the browser pipeline. Only tests use it: they run the same virtual-file-system +
// WebAssembly scan as the web page, and compare it with the native scanner (tests/web-parity.test.ts).
export { initParser } from "./browser-parser";
export { scanFiles, ROOT } from "./scan";
export type { MountedFile } from "./scan";
