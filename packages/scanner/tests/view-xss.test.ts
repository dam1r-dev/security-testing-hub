import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { scanPath } from "../src";

jest.setTimeout(60_000);

function project(files: Record<string, string>): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "hub-views-"));
  for (const [name, body] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(dir, name)), { recursive: true });
    fs.writeFileSync(path.join(dir, name), body);
  }
  return dir;
}

function xss(dir: string): Array<{ file: string; line: number; message: string }> {
  return scanPath(dir, { config: false }).results.flatMap((r) =>
    r.findings.filter((f) => f.ruleId === "xss").map((f) => ({ file: path.basename(r.file), line: f.location.startLine, message: f.message })),
  );
}

const route = (view: string, data: string): string =>
  `const express = require('express');\nconst app = express();\napp.post('/profile', (req, res) => {\n  res.render('${view}', ${data});\n});\n`;

describe("XSS through a view engine (0.8)", () => {
  it("EJS: <%- bio %> is reported, <%= name %> is not", () => {
    const dir = project({
      "app.js": route("profile", "{ bio: req.body.bio, name: req.body.name }"),
      "views/profile.ejs": "<h1><%= name %></h1>\n<div><%- bio %></div>\n",
    });
    const hits = xss(dir);
    expect(hits).toHaveLength(1);
    expect(hits[0]?.message).toMatch(/The view prints raw: views[\\/]profile\.ejs:2 \(<%- bio %>\)/);
  });

  it("EJS: only the keys printed raw count, and a value escaped on the way out is fine", () => {
    const safe = project({
      "app.js": route("profile", "{ name: req.body.name, bio: req.body.bio }"),
      "views/profile.ejs": "<h1><%= name %></h1>\n<div><%- escapeHtml(bio) %></div>\n<p><%- title %></p>\n",
    });
    expect(xss(safe)).toHaveLength(0); // title is not handed in by the request; bio is escaped
  });

  it("Pug: !{bio} and p!= bio are reported, #{bio} and p= bio are not", () => {
    const dir = project({
      "app.js": route("page", "{ bio: req.query.bio, about: req.query.about, safe: req.query.s, plain: req.query.p }"),
      "views/page.pug": "div\n  p!= bio\n  p #{safe}\n  p= plain\n  span !{about}\n",
    });
    const hits = xss(dir);
    expect(hits).toHaveLength(1); // one finding per render call, naming the first raw print
    expect(hits[0]?.message).toMatch(/page\.pug:2/);
    const escaped = project({ "app.js": route("page", "{ safe: req.query.s, plain: req.query.p }"), "views/page.pug": "div\n  p #{safe}\n  p= plain\n" });
    expect(xss(escaped)).toHaveLength(0);
  });

  it("Handlebars: {{{bio}}} and {{& bio}} are reported, {{bio}} is not", () => {
    const raw = project({ "app.js": route("home", "{ bio: req.body.bio }"), "views/home.hbs": "<p>{{{bio}}}</p>\n" });
    expect(xss(raw)).toHaveLength(1);
    const amp = project({ "app.js": route("home", "{ bio: req.body.bio }"), "views/home.handlebars": "<p>{{& bio}}</p>\n" });
    expect(xss(amp)).toHaveLength(1);
    const escaped = project({ "app.js": route("home", "{ bio: req.body.bio }"), "views/home.hbs": "<p>{{bio}}</p>\n" });
    expect(xss(escaped)).toHaveLength(0);
  });

  it("Nunjucks: {{ bio | safe }}", () => {
    const dir = project({ "app.js": route("home", "{ bio: req.body.bio }"), "views/home.njk": "<p>{{ bio | safe }}</p>\n" });
    expect(xss(dir)).toHaveLength(1);
  });

  it("a partial the view includes counts; an implicit layout's {{{body}}} does not", () => {
    const dir = project({
      "app.js": route("page", "{ bio: req.body.bio, body: req.body.b }"),
      "views/page.ejs": "<main><%- include('partials/bio') %></main>\n",
      "views/partials/bio.ejs": "<div><%- bio %></div>\n",
      "views/layouts/main.hbs": "<html>{{{body}}}</html>\n",
    });
    const hits = xss(dir);
    expect(hits).toHaveLength(1);
    expect(hits[0]?.message).toMatch(/partials[\\/]bio\.ejs:1/);
  });

  it("shorthand properties, a template name with its extension, and other frameworks' render calls", () => {
    const dir = project({
      "app.js": "app.get('/a', (req, res) => { const bio = req.query.bio; res.render('profile.ejs', { bio }); });\napp.get('/b', async (request, reply) => reply.view('profile', { bio: request.query.bio }));\n",
      "views/profile.ejs": "<%- bio %>\n",
    });
    expect(xss(dir)).toHaveLength(2);
  });

  it("nothing is guessed: a view that is not found, a value that is not the caller's, JSON bodies", () => {
    expect(xss(project({ "app.js": route("missing", "{ bio: req.body.bio }") }))).toHaveLength(0);
    expect(xss(project({ "app.js": route("profile", "{ bio: 'static text' }"), "views/profile.ejs": "<%- bio %>\n" }))).toHaveLength(0);
    expect(xss(project({ "app.js": "app.get('/j', (req, res) => res.json({ bio: req.body.bio }));\n", "views/profile.ejs": "<%- bio %>\n" }))).toHaveLength(0);
  });
});

describe("template engine escaping switched off (0.8)", () => {
  it("swig.setDefaults({ autoescape: false }) is a finding, with or without a flow", () => {
    const dir = project({ "server.js": "const swig = require('swig');\n// Template system setup\nswig.setDefaults({\n  // Autoescape disabled\n  autoescape: false\n});\n" });
    const hits = xss(dir);
    expect(hits).toHaveLength(1);
    expect(hits[0]?.message).toMatch(/set to print every value without escaping \(autoescape: false\)/);
    expect(xss(project({ "server.js": "nunjucks.configure('views', { autoescape: false, express: app });\n" }))).toHaveLength(1);
    expect(xss(project({ "server.js": "const env = new nunjucks.Environment(loader, { autoescape: false });\n" }))).toHaveLength(1);
    expect(xss(project({ "server.js": "const t = Handlebars.compile(source, { noEscape: true });\n" }))).toHaveLength(1);
    // escaping left on (the default, or said out loud) is nothing
    expect(xss(project({ "server.js": "swig.setDefaults({ autoescape: true });\nnunjucks.configure('views', { autoescape: true });\n" }))).toHaveLength(0);
  });

  it("with escaping off, a plain {{ value }} in a Swig / Nunjucks view is raw", () => {
    const dir = project({
      "server.js": "swig.setDefaults({ autoescape: false });\n",
      "routes.js": route("memos", "{ memo: req.body.memo, shown: req.body.s }"),
      "views/memos.html": "<p>{{ memo }}</p>\n<p>{{ shown | escape }}</p>\n",
    });
    const hits = xss(dir).filter((h) => h.file === "routes.js");
    expect(hits).toHaveLength(1);
    expect(hits[0]?.message).toMatch(/memos\.html:1 \(\{\{ memo \}\} with autoescape turned off\)/);
  });

  it("with escaping on (the default), the same view is safe", () => {
    const dir = project({ "routes.js": route("memos", "{ memo: req.body.memo }"), "views/memos.html": "<p>{{ memo }}</p>\n" });
    expect(xss(dir)).toHaveLength(0);
  });
});
