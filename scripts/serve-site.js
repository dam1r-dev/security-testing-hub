#!/usr/bin/env node
// Serves ./site on http://127.0.0.1:4173 to try the page (and its in-browser scanner) before it is published.
// A Web Worker cannot start from a file:// address, so opening site/index.html directly will not scan folders.
//   npm run site:scanner && npm run site:serve
const http = require("http");
const fs = require("fs");
const path = require("path");

const site = path.resolve(__dirname, "..", "site");
const port = Number(process.env.PORT) || 4173;
const TYPES = { ".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".wasm": "application/wasm", ".png": "image/png", ".md": "text/plain; charset=utf-8" };

http
  .createServer((request, response) => {
    const pathname = decodeURIComponent((request.url || "/").split("?")[0]);
    const file = path.resolve(site, "." + (pathname.endsWith("/") ? pathname + "index.html" : pathname));
    // never leave the site folder, whatever the address says
    if (file !== site && !file.startsWith(site + path.sep)) {
      response.writeHead(403).end("Forbidden");
      return;
    }
    fs.readFile(file, (error, content) => {
      if (error) {
        response.writeHead(404).end("Not found");
        return;
      }
      response.writeHead(200, { "Content-Type": TYPES[path.extname(file)] || "application/octet-stream", "Cache-Control": "no-store" });
      response.end(content);
    });
  })
  .listen(port, "127.0.0.1", () => console.log(`site on http://127.0.0.1:${port}/`));
