import * as fs from "fs";
import * as path from "path";
import { applyInlineSuppressions } from "../suppress";
import { Finding } from "../types";

/**
 * `missing-security-headers`: a web app that never sets the response headers browsers use as a second line of defence
 * (Content-Security-Policy, X-Content-Type-Options, X-Frame-Options, Strict-Transport-Security). One finding per project, on the line that
 * creates the app (`express()`, `Flask(__name__)`, `FastAPI()`, `fastify()`, `new Koa()`), only when nothing anywhere in the project sets any
 * of them: no helmet / Talisman / secure-headers package, no header written by hand, no `vercel.json` / `netlify.toml` / `_headers` / nginx
 * config that does. Reported with LOW severity and LOW confidence: a reverse proxy or CDN in front of the app may set them, and the scanner
 * cannot see that.
 *
 * Django is not judged: its SecurityMiddleware is on by default.
 */

const APP = /\bexpress\s*\(\s*\)|\bFlask\s*\(\s*(?:__name__|["'])|\bFastAPI\s*\(|\bfastify\s*\(|\bnew\s+Koa\s*\(/;
const LISTENS = /\.listen\s*\(|app\.run\s*\(|uvicorn|serve\(|module\.exports\s*=\s*app|export\s+default\s+app/;
// The project serves pages or files to a browser. A pure JSON API has little for a CSP or X-Frame-Options to protect, so it is not judged.
const SERVES_PAGES = /render_template|render_template_string|HTMLResponse|Jinja2Templates|TemplateResponse|StaticFiles|express\.static|res\.render\s*\(|sendFile\s*\(|send_from_directory|view engine|<!doctype html|<html[\s>]/i;
const HEADER_EVIDENCE =
  /helmet|secure-?headers|secure_headers|Talisman|flask[_-]csp|SecurityHeaders|lusca|Content-Security-Policy|X-Frame-Options|X-Content-Type-Options|Strict-Transport-Security|Referrer-Policy|Permissions-Policy|secure\.Secure\b/i;
const HOST_CONFIGS = ["vercel.json", "netlify.toml", "_headers", "public/_headers", "nginx.conf", "Caddyfile", ".htaccess", "firebase.json", "staticwebapp.config.json", "render.yaml"];

interface Candidate {
  file: string;
  text: string;
  index: number;
  listens: boolean;
}

export class HeaderEvidence {
  private candidate: Candidate | undefined;
  private evidence = false;
  private pages = false;

  /** Feed every source file of the scan (cheap: a few regular expressions). */
  add(file: string, text: string): void {
    if (this.evidence) return;
    if (HEADER_EVIDENCE.test(text)) {
      this.evidence = true;
      return;
    }
    if (!this.pages && SERVES_PAGES.test(text)) this.pages = true;
    const match = APP.exec(text);
    if (!match) return;
    const listens = LISTENS.test(text);
    if (!this.candidate || (listens && !this.candidate.listens)) this.candidate = { file, text, index: match.index, listens };
  }

  /** The finding, with the file it belongs to. Undefined when the project sets headers, or has no web app. */
  finding(root: string): { file: string; finding: Finding; kept: boolean } | undefined {
    const candidate = this.candidate;
    if (this.evidence || !this.pages || !candidate) return undefined;
    for (const name of HOST_CONFIGS) {
      try {
        if (HEADER_EVIDENCE.test(fs.readFileSync(path.join(root, name), "utf8").slice(0, 200_000))) return undefined;
      } catch {
        // no such file
      }
    }
    const before = candidate.text.slice(0, candidate.index);
    const startLine = before.split("\n").length;
    const lineStart = before.lastIndexOf("\n") + 1;
    const lineEnd = candidate.text.indexOf("\n", candidate.index);
    const line = candidate.text.slice(lineStart, lineEnd === -1 ? undefined : lineEnd);
    const finding: Finding = {
      ruleId: "missing-security-headers",
      severity: "low",
      confidence: "low",
      message:
        "Nothing in this project sets the browser security headers (Content-Security-Policy, X-Content-Type-Options, X-Frame-Options, Strict-Transport-Security). " +
        "They limit what a stored script can do, stop the site being framed for clickjacking and force HTTPS. Add helmet() in Express, Flask-Talisman in Flask, " +
        "or the headers in your proxy. (Low confidence: a reverse proxy or CDN in front of the app may already set them.)",
      location: { file: candidate.file, startLine, startColumn: candidate.index - lineStart + 1, endLine: startLine, endColumn: candidate.index - lineStart + 1 + line.trim().length },
      sourceSnippet: "(project-wide check)",
      sinkSnippet: line.trim().slice(0, 160),
    };
    const { kept } = applyInlineSuppressions([finding], candidate.text);
    return { file: candidate.file, finding, kept: kept.length > 0 };
  }
}
