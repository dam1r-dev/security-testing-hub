import * as crypto from "crypto";
import * as fs from "fs";
import * as http from "http";
import * as os from "os";
import * as path from "path";
import { spawn } from "child_process";
import chalk from "chalk";
import { computeScore, fixPromptFor, scanPath, toFixPrompt, toHtml } from "security-hub-scanner";
import { renderUiPage } from "./ui-page";

// eslint-disable-next-line @typescript-eslint/no-var-requires, @typescript-eslint/no-require-imports
const PACKAGE_VERSION: string = require("../../package.json").version;

const DEFAULT_PORT = 4173;
const PORT_ATTEMPTS = 20;
const MAX_BODY_BYTES = 16 * 1024;
const MAX_BROWSE_ENTRIES = 500;

export interface UiOptions {
  /** Folder pre-filled in the page. */
  path?: string;
  port?: number;
  /** Open the default browser after starting (default true). */
  open?: boolean;
}

export interface UiServer {
  server: http.Server;
  port: number;
  url: string;
  token: string;
}

class HttpError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
  }
}

// The UI reads arbitrary folders on this machine, so it must not be reachable
// from anything but the user's own browser tab:
//  - it binds to 127.0.0.1 only;
//  - the Host header must be the loopback address (blocks DNS rebinding);
//  - every /api call needs a per-run random token that only the served page
//    knows (a page on another origin can't read it, so it can't drive the API);
//  - POSTs must come from our own origin;
//  - a strict CSP keeps scanned code from running inside the page.
function isAllowedHost(req: http.IncomingMessage, port: number): boolean {
  const host = req.headers.host;
  return host === `127.0.0.1:${port}` || host === `localhost:${port}`;
}

function hasValidToken(req: http.IncomingMessage, token: string): boolean {
  const supplied = req.headers["x-security-hub-token"];
  if (typeof supplied !== "string") return false;
  const a = Buffer.from(supplied);
  const b = Buffer.from(token);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function sendJson(res: http.ServerResponse, status: number, body: unknown): void {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
  });
  res.end(payload);
}

function readJsonBody(req: http.IncomingMessage): Promise<Record<string, unknown>> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    req.on("data", (chunk: Buffer) => {
      size += chunk.length;
      if (size > MAX_BODY_BYTES) {
        reject(new HttpError(413, "Request too large"));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => {
      try {
        const parsed: unknown = JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}");
        if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
          throw new Error("not an object");
        }
        resolve(parsed as Record<string, unknown>);
      } catch {
        reject(new HttpError(400, "Invalid JSON body"));
      }
    });
    req.on("error", reject);
  });
}

/** `"C:\my app"` (Windows "Copy as path") and stray whitespace are both fine to paste. */
function normalizeUserPath(input: string): string {
  return path.resolve(input.trim().replace(/^["']+|["']+$/g, ""));
}

interface BrowseRoot {
  name: string;
  path: string;
}

function browseRoots(): BrowseRoot[] {
  const roots: BrowseRoot[] = [{ name: "Home", path: os.homedir() }];
  const desktop = path.join(os.homedir(), "Desktop");
  if (fs.existsSync(desktop)) roots.push({ name: "Desktop", path: desktop });
  if (process.platform === "win32") {
    for (let code = 65; code <= 90; code++) {
      const drive = `${String.fromCharCode(code)}:\\`;
      if (fs.existsSync(drive)) roots.push({ name: `${String.fromCharCode(code)}:`, path: drive });
    }
  } else {
    roots.push({ name: "/", path: path.parse(os.homedir()).root });
  }
  return roots;
}

function browse(requestedDir: string | null, fallbackDir: string) {
  let dir = normalizeUserPath(requestedDir || fallbackDir);
  // A path to a file (or one that vanished) opens its nearest existing folder instead of failing.
  while (!fs.existsSync(dir) || !fs.statSync(dir).isDirectory()) {
    const parent = path.dirname(dir);
    if (parent === dir) throw new HttpError(404, `Folder not found: ${requestedDir ?? fallbackDir}`);
    dir = parent;
  }

  let dirents: fs.Dirent[];
  try {
    dirents = fs.readdirSync(dir, { withFileTypes: true });
  } catch (err) {
    throw new HttpError(403, `Cannot read ${dir}: ${(err as Error).message}`);
  }

  const entries = dirents
    .filter((d) => d.isDirectory() && !d.name.startsWith(".") && d.name !== "node_modules")
    .sort((a, b) => a.name.localeCompare(b.name))
    .slice(0, MAX_BROWSE_ENTRIES)
    .map((d) => {
      const full = path.join(dir, d.name);
      return { name: d.name, path: full, isProject: fs.existsSync(path.join(full, "package.json")) };
    });

  const parent = path.dirname(dir);
  return { dir, parent: parent === dir ? null : parent, entries, roots: browseRoots() };
}

function scan(rawPath: unknown) {
  if (typeof rawPath !== "string" || rawPath.trim() === "") throw new HttpError(400, "Enter a folder path first.");
  const target = normalizeUserPath(rawPath);
  if (!fs.existsSync(target)) throw new HttpError(404, `Path not found: ${target}`);

  const summary = scanPath(target);
  return {
    target,
    // Files with nothing to report are dropped: a large project has thousands of them.
    results: summary.results
      .filter((r) => r.findings.length > 0 || r.parseError)
      .map((r) => ({ ...r, findings: r.findings.map((f) => ({ ...f, fixPrompt: fixPromptFor(f, { relativeTo: target }) })) })),
    allPrompt: toFixPrompt(summary, { relativeTo: target }),
    summary: {
      filesScanned: summary.filesScanned,
      findingsCount: summary.findingsCount,
      durationMs: summary.durationMs,
      suppressedCount: summary.suppressedCount ?? 0,
    },
    score: computeScore(summary),
    html: toHtml(summary, target),
  };
}

function handle(
  req: http.IncomingMessage,
  res: http.ServerResponse,
  state: { port: number; token: string; options: UiOptions },
): Promise<void> | void {
  if (!isAllowedHost(req, state.port)) {
    throw new HttpError(403, "Forbidden host");
  }
  const url = new URL(req.url ?? "/", `http://127.0.0.1:${state.port}`);

  if (req.method === "GET" && url.pathname === "/") {
    const nonce = crypto.randomBytes(16).toString("base64");
    const html = renderUiPage({
      token: state.token,
      nonce,
      initialPath: path.resolve(state.options.path ?? process.cwd()),
      explicitPath: state.options.path !== undefined,
      version: PACKAGE_VERSION,
    });
    res.writeHead(200, {
      "content-type": "text/html; charset=utf-8",
      "cache-control": "no-store",
      "x-content-type-options": "nosniff",
      "referrer-policy": "no-referrer",
      "content-security-policy":
        `default-src 'none'; script-src 'nonce-${nonce}'; style-src 'unsafe-inline'; ` +
        `connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'`,
    });
    res.end(html);
    return;
  }

  if (url.pathname.startsWith("/api/")) {
    if (!hasValidToken(req, state.token)) throw new HttpError(403, "Missing or invalid token");
    if (req.method === "GET" && url.pathname === "/api/browse") {
      sendJson(res, 200, browse(url.searchParams.get("dir"), state.options.path ?? process.cwd()));
      return;
    }
    if (req.method === "POST" && url.pathname === "/api/scan") {
      const origin = req.headers.origin;
      if (origin !== undefined && origin !== `http://${req.headers.host}`) throw new HttpError(403, "Bad origin");
      return readJsonBody(req).then((body) => sendJson(res, 200, scan(body.path)));
    }
  }

  throw new HttpError(404, "Not found");
}

function listen(server: http.Server, port: number): Promise<number> {
  return new Promise((resolve, reject) => {
    const onError = (err: Error): void => reject(err);
    server.once("error", onError);
    server.listen(port, "127.0.0.1", () => {
      server.off("error", onError);
      resolve((server.address() as { port: number }).port);
    });
  });
}

/** Starts the local UI server. `port: 0` picks any free port; otherwise the next free one at or after `port`. */
export async function startUiServer(options: UiOptions = {}): Promise<UiServer> {
  const state = { port: 0, token: crypto.randomBytes(24).toString("hex"), options };
  const server = http.createServer((req, res) => {
    const fail = (err: unknown): void => {
      const status = err instanceof HttpError ? err.status : 500;
      const message = err instanceof HttpError ? err.message : `Scan failed: ${(err as Error).message}`;
      if (!res.headersSent) sendJson(res, status, { error: message });
      else res.end();
    };
    try {
      const pending = handle(req, res, state);
      if (pending) pending.catch(fail);
    } catch (err) {
      fail(err);
    }
  });

  const first = options.port ?? DEFAULT_PORT;
  const attempts = first === 0 ? 1 : PORT_ATTEMPTS;
  for (let i = 0; i < attempts; i++) {
    try {
      state.port = await listen(server, first === 0 ? 0 : first + i);
      return { server, port: state.port, url: `http://127.0.0.1:${state.port}/`, token: state.token };
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== "EADDRINUSE" || i === attempts - 1) throw err;
    }
  }
  throw new Error("unreachable");
}

function openInBrowser(url: string): void {
  const [command, args] =
    process.platform === "win32"
      ? ["cmd", ["/c", "start", "", url]]
      : process.platform === "darwin"
        ? ["open", [url]]
        : ["xdg-open", [url]];
  try {
    const child = spawn(command as string, args as string[], { stdio: "ignore", detached: true });
    child.on("error", () => undefined); // no browser available: the URL is printed anyway
    child.unref();
  } catch {
    // ignore
  }
}

/** `security-hub ui`: serve the local web interface until Ctrl+C. */
export async function runUi(options: UiOptions): Promise<number> {
  if (options.path !== undefined && !fs.existsSync(options.path)) {
    process.stderr.write(chalk.red(`Path not found: ${options.path}\n`));
    return 2;
  }
  let ui: UiServer;
  try {
    ui = await startUiServer(options);
  } catch (err) {
    process.stderr.write(chalk.red(`Could not start the UI server: ${(err as Error).message}\n`));
    return 1;
  }
  process.stdout.write(`${chalk.green("Security Testing Hub is running:")} ${chalk.bold(ui.url)}\n`);
  process.stdout.write(chalk.dim("Local only — your code never leaves this computer. Press Ctrl+C to stop.\n"));
  if (options.open !== false) openInBrowser(ui.url);
  return 0;
}
