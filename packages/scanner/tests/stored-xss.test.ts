import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { keyAliases } from "../src/templates";
import { scanPath } from "../src";

jest.setTimeout(60_000);

function project(files: Record<string, string>): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "hub-stored-"));
  for (const [name, body] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(dir, name)), { recursive: true });
    fs.writeFileSync(path.join(dir, name), body);
  }
  return dir;
}

function xss(dir: string): Array<{ file: string; line: number; message: string; confidence: string }> {
  return scanPath(dir, { config: false }).results.flatMap((r) =>
    r.findings.filter((f) => f.ruleId === "xss").map((f) => ({ file: path.basename(r.file), line: f.location.startLine, message: f.message, confidence: f.confidence })),
  );
}

describe("a loop variable in a template stands for the list it iterates (round 18)", () => {
  it("finds the names a template gives to a handed-in key", () => {
    expect(keyAliases("{% for post in posts %}{{ post.body }}{% endfor %}", "posts", "jinja")).toEqual(["posts", "post"]);
    expect(keyAliases("{% for k, v in posts %}{% set first = v.items %}", "posts", "jinja")).toEqual(expect.arrayContaining(["posts", "k", "v", "first"]));
    expect(keyAliases("<% posts.forEach(function (post) { %><%- post.body %><% }) %>", "posts", "ejs")).toEqual(["posts", "post"]);
    expect(keyAliases("<% for (const post of posts) { %>", "posts", "ejs")).toEqual(["posts", "post"]);
    expect(keyAliases("each post in posts\n  p!= post.body", "posts", "pug")).toEqual(["posts", "post"]);
    expect(keyAliases("{% for post in other %}", "posts", "jinja")).toEqual(["posts"]);
  });

  it("a raw print of the loop variable is a raw print of the list (handed in from the request)", () => {
    const route = "app.get('/s', (req, res) => { res.render('list', { posts: JSON.parse(req.query.posts) }); });\n";
    expect(xss(project({ "app.js": route, "views/list.ejs": "<% posts.forEach(function (post) { %><li><%- post.body %></li><% }) %>" }))).toHaveLength(1);
    expect(xss(project({ "app.js": route, "views/list.pug": "each post in posts\n  li!= post.body\n" }))).toHaveLength(1);
    expect(xss(project({ "app.js": route, "views/list.hbs": "{{#each posts}}<li>{{{body}}}</li>{{/each}}" }))).toHaveLength(1);
    expect(xss(project({ "app.js": route, "views/list.ejs": "<% posts.forEach(function (post) { %><li><%= post.body %></li><% }) %>" }))).toHaveLength(0);
  });
});

describe("stored XSS: database rows printed raw (round 18)", () => {
  it("a DAO with a callback (the NodeGoat memos page)", () => {
    const dir = project({
      "server.js": "swig.setDefaults({ autoescape: false });\n",
      "routes/memos.js": "function MemosHandler(db) {\n  const memosDAO = new MemosDAO(db);\n  this.displayMemos = (req, res) => {\n    memosDAO.getAllMemos((err, docs) => {\n      if (err) return next(err);\n      return res.render('memos', { memosList: docs, user: req.session.user });\n    });\n  };\n}\n",
      "views/memos.html": "{% for memo in memosList %}<p>{{ memo.memo }}</p>{% endfor %}\n",
    });
    const hits = xss(dir).filter((h) => h.file === "memos.js");
    expect(hits).toHaveLength(1);
    expect(hits[0]?.confidence).toBe("low");
    expect(hits[0]?.message).toMatch(/`docs` was read from the database.*memosList.*memos\.html:1/);
  });

  it("a model with await, a pool with a promise, mongoose with populate", () => {
    const raw = "<ul><% posts.forEach(function (p) { %><li><%- p.html %></li><% }) %></ul>\n";
    const awaited = project({ "app.js": "app.get('/', async (req, res) => {\n  const posts = await Post.find({ published: true }).populate('author').lean();\n  res.render('index', { posts });\n});\n", "views/index.ejs": raw });
    expect(xss(awaited)).toHaveLength(1);
    const pool = project({ "app.js": "app.get('/', (req, res) => {\n  pool.query('SELECT * FROM posts').then((result) => res.render('index', { posts: result.rows }));\n});\n", "views/index.ejs": raw });
    expect(xss(pool)).toHaveLength(1);
    const prisma = project({ "app.js": "app.get('/', async (req, res) => {\n  const rows = await prisma.post.findMany();\n  const posts = rows.filter((r) => r.ok);\n  res.render('index', { posts });\n});\n", "views/index.ejs": raw });
    expect(xss(prisma)).toHaveLength(1);
  });

  it("silent when the view escapes, when the value is not from a database, or the view is not found", () => {
    const escaped = project({ "app.js": "app.get('/', async (req, res) => { const posts = await Post.find(); res.render('index', { posts }); });\n", "views/index.ejs": "<% posts.forEach(function (p) { %><li><%= p.html %></li><% }) %>\n" });
    expect(xss(escaped)).toHaveLength(0);
    const notDb = project({ "app.js": "app.get('/', async (req, res) => { const posts = ['a', 'b']; const n = Math.max(1, 2); res.render('index', { posts, n }); });\n", "views/index.ejs": "<%- posts %><%- n %>\n" });
    expect(xss(notDb)).toHaveLength(0);
    const array = project({ "app.js": "app.get('/', (req, res) => { const found = Array.find; const x = items.find((i) => i.ok); res.render('index', { x }); });\n", "views/index.ejs": "<%- x %>\n" });
    expect(xss(array)).toHaveLength(0);
    const missing = project({ "app.js": "app.get('/', async (req, res) => { const posts = await Post.find(); res.render('nope', { posts }); });\n" });
    expect(xss(missing)).toHaveLength(0);
  });

  it("a value that is not handed to the view is not judged (the key the view prints raw must be the database one)", () => {
    const dir = project({
      "app.js": "app.get('/', async (req, res) => { const posts = await Post.find(); res.render('index', { posts, banner: 'hi' }); });\n",
      "views/index.ejs": "<%- banner %>\n<% posts.forEach(function (p) { %><li><%= p.title %></li><% }) %>\n",
    });
    expect(xss(dir)).toHaveLength(0); // banner is printed raw but is a constant; posts is escaped
  });
});

describe("one finding per call", () => {
  it("a render call that hands in both a request value and a database row raw is reported once (the request one, which is surer)", () => {
    const dir = project({
      "app.js": "app.get('/a/:id', async (req, res) => {\n  const rows = await Allocation.find();\n  res.render('a', { userId: req.params.id, rows });\n});\n",
      "views/a.ejs": "<%- userId %>\n<% rows.forEach(function (r) { %><%- r.note %><% }) %>\n",
    });
    const hits = xss(dir);
    expect(hits).toHaveLength(1);
    expect(hits[0]?.confidence).toBe("medium");
    expect(hits[0]?.message).toMatch(/User-controlled input/);
  });
});

describe("stored XSS in Python and PHP views (round 18)", () => {
  it("Flask: an ORM query handed to a template that prints it with |safe", () => {
    const dir = project({
      "app.py": "from flask import Flask, render_template\napp = Flask(__name__)\n\n@app.route('/')\ndef index():\n    posts = Post.query.order_by(Post.id).all()\n    return render_template('list.html', posts=posts)\n",
      "templates/list.html": "{% for post in posts %}<p>{{ post.body|safe }}</p>{% endfor %}\n",
    });
    const hits = xss(dir).filter((h) => h.file === "app.py");
    expect(hits).toHaveLength(1);
    expect(hits[0]?.confidence).toBe("low");
    expect(hits[0]?.message).toMatch(/read from the database/);
  });

  it("Flask: silent when the template escapes, or the value is not from a database", () => {
    const escaped = project({
      "app.py": "from flask import Flask, render_template\napp = Flask(__name__)\n\n@app.route('/')\ndef index():\n    posts = Post.query.all()\n    return render_template('list.html', posts=posts)\n",
      "templates/list.html": "{% for post in posts %}<p>{{ post.body }}</p>{% endfor %}\n",
    });
    expect(xss(escaped)).toHaveLength(0);
    const constant = project({
      "app.py": "from flask import Flask, render_template\napp = Flask(__name__)\n\n@app.route('/')\ndef index():\n    posts = ['a', 'b']\n    return render_template('list.html', posts=posts)\n",
      "templates/list.html": "{% for post in posts %}<p>{{ post|safe }}</p>{% endfor %}\n",
    });
    expect(xss(constant)).toHaveLength(0);
  });

  it("Laravel: Eloquent rows handed to a Blade view that prints {!! !!}", () => {
    const dir = project({
      "app/Http/Controllers/PostController.php": "<?php\nclass PostController {\n  public function index() {\n    $posts = Post::latest()->get();\n    return view('posts', compact('posts'));\n  }\n}\n",
      "resources/views/posts.blade.php": "@foreach ($posts as $post)<p>{!! $post->body !!}</p>@endforeach\n",
    });
    const hits = xss(dir).filter((h) => h.file === "PostController.php");
    expect(hits).toHaveLength(1);
    expect(hits[0]?.confidence).toBe("low");
  });

  it("Laravel: silent when the view escapes", () => {
    const dir = project({
      "app/Http/Controllers/PostController.php": "<?php\nclass PostController {\n  public function index() {\n    $posts = Post::latest()->get();\n    return view('posts', compact('posts'));\n  }\n}\n",
      "resources/views/posts.blade.php": "@foreach ($posts as $post)<p>{{ $post->body }}</p>@endforeach\n",
    });
    expect(xss(dir)).toHaveLength(0);
  });
});
