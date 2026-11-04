import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { scanPath } from "../src";

jest.setTimeout(60_000);

function project(files: Record<string, string>): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "hub-exposure-"));
  for (const [name, body] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(dir, name)), { recursive: true });
    fs.writeFileSync(path.join(dir, name), body);
  }
  return dir;
}

function hits(dir: string, rule: string): Array<{ file: string; line: number; confidence: string; severity: string }> {
  return scanPath(dir, { config: false }).results.flatMap((r) =>
    r.findings.filter((f) => f.ruleId === rule).map((f) => ({ file: path.basename(r.file), line: f.location.startLine, confidence: f.confidence, severity: f.severity })),
  );
}

describe("debug-endpoint: JavaScript", () => {
  it("the whole environment in a response", () => {
    const dir = project({
      "app.js": [
        "app.get('/a', (req, res) => res.json(process.env));",
        "app.get('/b', (req, res) => { res.status(200).send(JSON.stringify(process.env)); });",
        "export async function GET() { return NextResponse.json({ env: process.env }); }",
        "app.get('/ok1', (req, res) => res.json({ node: process.env.NODE_ENV }));",
        "app.get('/ok2', (req, res) => res.json({ v: process.env['VERSION'] }));",
        "const port = process.env.PORT || 3000;",
        "",
      ].join("\n"),
    });
    const found = hits(dir, "debug-endpoint");
    expect(found.map((h) => h.line)).toEqual([1, 2, 3]);
    expect(found.every((h) => h.severity === "high")).toBe(true);
  });

  it("a debug route without a login check; silent when it is guarded or is a normal route", () => {
    const dir = project({
      "app.js": [
        "app.get('/debug', (req, res) => { res.json({ uptime: process.uptime(), query: req.query }); });",
        "app.get('/_debug/sessions', requireAdmin, (req, res) => { res.json(store.all()); });",
        "if (process.env.NODE_ENV !== 'production') app.get('/debug/env', (req, res) => res.json({ ok: true }));",
        "app.get('/health', (req, res) => res.json({ ok: true }));",
        "app.get('/debugging-tips', (req, res) => res.send('tips'));",
        "",
      ].join("\n"),
    });
    const found = hits(dir, "debug-endpoint");
    expect(found.map((h) => h.line)).toEqual([1]);
    expect(found[0]?.confidence).toBe("low");
  });

  it("GraphQL introspection and GraphiQL switched on without a condition", () => {
    const dir = project({
      "server.js": [
        "const a = new ApolloServer({ typeDefs, resolvers, introspection: true });",
        "const b = new ApolloServer({ typeDefs, resolvers, introspection: process.env.NODE_ENV !== 'production' });",
        "app.use('/graphql', graphqlHTTP({ schema, graphiql: true }));",
        "",
      ].join("\n"),
    });
    expect(hits(dir, "debug-endpoint").map((h) => h.line)).toEqual([1, 3]);
  });
});

describe("debug-endpoint: Python", () => {
  it("the whole environment or config in a response", () => {
    const dir = project({
      "app.py": [
        "from flask import Flask, jsonify",
        "import os",
        "app = Flask(__name__)",
        "@app.route('/env')",
        "def env():",
        "    return jsonify(dict(os.environ))",
        "@app.route('/cfg')",
        "def cfg():",
        "    return jsonify(app.config)",
        "@app.route('/txt')",
        "def txt():",
        "    return str(os.environ)",
        "@app.route('/ok')",
        "def ok():",
        "    return jsonify(mode=os.environ.get('MODE'), key=os.environ['KEY'][:2])",
        "",
      ].join("\n"),
    });
    expect(hits(dir, "debug-endpoint").map((h) => h.line)).toEqual([6, 9, 12]);
  });

  it("a debug route without a login check", () => {
    const dir = project({
      "app.py": [
        "from flask import Flask, request",
        "app = Flask(__name__)",
        "@app.route('/debug')",
        "def debug():",
        "    return str(request.headers)",
        "@app.route('/debug/admin')",
        "@login_required",
        "def debug_admin():",
        "    return 'x'",
        "",
      ].join("\n"),
    });
    expect(hits(dir, "debug-endpoint").map((h) => h.line)).toEqual([4]);
  });
});

describe("debug-endpoint: PHP", () => {
  it("phpinfo() and the environment dumped", () => {
    const dir = project({
      "info.php": "<?php\nphpinfo();\n",
      "dump.php": "<?php\nprint_r($_ENV);\nvar_dump($_SERVER);\necho json_encode(getenv());\nvar_dump($_SERVER['HTTP_HOST']);\nvar_dump(getenv('APP_ENV'));\n",
    });
    expect(hits(dir, "debug-endpoint").map((h) => `${h.file}:${h.line}`).sort()).toEqual(["dump.php:2", "dump.php:3", "dump.php:4", "info.php:2"]);
  });

  it("phpinfo() behind a login is reported with low confidence; a CLI-only script is not", () => {
    const behind = project({ "info.php": "<?php\nrequire 'auth.php'; if (!isAdmin()) die();\nphpinfo();\n" });
    expect(hits(behind, "debug-endpoint")[0]?.confidence).toBe("low");
    const cli = project({ "tool.php": "<?php\nif (php_sapi_name() === 'cli') { phpinfo(); }\n" });
    expect(hits(cli, "debug-endpoint")).toHaveLength(0);
  });
});

describe("insecure-file-upload: Python and PHP", () => {
  it("Flask: the client's file name used as it is", () => {
    const dir = project({
      "app.py": [
        "from flask import Flask, request",
        "import os",
        "app = Flask(__name__)",
        "@app.route('/up', methods=['POST'])",
        "def up():",
        "    f = request.files['file']",
        "    f.save(os.path.join('uploads', f.filename))",
        "    return 'ok'",
        "@app.route('/up2', methods=['POST'])",
        "def up2():",
        "    f = request.files['file']",
        "    name = f.filename",
        "    f.save('uploads/' + name)",
        "    return 'ok'",
        "",
      ].join("\n"),
    });
    expect(hits(dir, "insecure-file-upload").map((h) => h.line)).toEqual([7, 13]);
  });

  it("Flask: silent with secure_filename, an extension check, or a generated name", () => {
    const dir = project({
      "app.py": [
        "from flask import Flask, request",
        "from werkzeug.utils import secure_filename",
        "import os, uuid",
        "app = Flask(__name__)",
        "@app.route('/a', methods=['POST'])",
        "def a():",
        "    f = request.files['file']",
        "    f.save(os.path.join('uploads', secure_filename(f.filename)))",
        "@app.route('/b', methods=['POST'])",
        "def b():",
        "    f = request.files['file']",
        "    if not f.filename.lower().endswith(('.png', '.jpg')): return 'no'",
        "    f.save(os.path.join('uploads', f.filename))",
        "@app.route('/c', methods=['POST'])",
        "def c():",
        "    f = request.files['file']",
        "    f.save(os.path.join('uploads', uuid.uuid4().hex))",
        "",
      ].join("\n"),
    });
    expect(hits(dir, "insecure-file-upload")).toHaveLength(0);
  });

  it("Flask: a project-specific sanitiser (safe_filename) counts, like secure_filename", () => {
    const dir = project({ "app.py": "from flask import Flask, request\napp = Flask(__name__)\n@app.route('/up', methods=['POST'])\ndef up():\n    f = request.files['file']\n    name = safe_filename(f.filename)\n    f.save('uploads/' + name)\n" });
    expect(hits(dir, "insecure-file-upload")).toHaveLength(0);
  });

  it("Django and FastAPI: open() / storage.save with the client's name", () => {
    const dir = project({
      "views.py": [
        "from django.core.files.storage import default_storage",
        "def upload(request):",
        "    f = request.FILES['doc']",
        "    default_storage.save(f.name, f)",
        "    with open('/srv/up/' + f.name, 'wb') as out:",
        "        out.write(f.read())",
        "",
      ].join("\n"),
      "main.py": [
        "from fastapi import FastAPI, UploadFile",
        "app = FastAPI()",
        "@app.post('/up')",
        "async def up(file: UploadFile):",
        "    with open(f'uploads/{file.filename}', 'wb') as out:",
        "        out.write(await file.read())",
        "",
      ].join("\n"),
    });
    const found = hits(dir, "insecure-file-upload").map((h) => `${h.file}:${h.line}`).sort();
    expect(found).toEqual(["main.py:5", "views.py:4", "views.py:5"]);
  });

  it("PHP: move_uploaded_file with the client's name, directly or through a variable", () => {
    const dir = project({
      "upload.php": "<?php\n$target = 'uploads/';\n$target .= basename($_FILES['f']['name']);\nmove_uploaded_file($_FILES['f']['tmp_name'], $target);\n",
      "direct.php": "<?php\nmove_uploaded_file($_FILES['f']['tmp_name'], 'up/' . $_FILES['f']['name']);\n",
      "safe.php": "<?php\n$ext = strtolower(pathinfo($_FILES['f']['name'], PATHINFO_EXTENSION));\nif (!in_array($ext, ['jpg', 'png'])) die();\nmove_uploaded_file($_FILES['f']['tmp_name'], 'up/' . bin2hex(random_bytes(8)) . '.' . $ext);\n",
      "random.php": "<?php\nmove_uploaded_file($_FILES['f']['tmp_name'], 'up/' . bin2hex(random_bytes(8)));\n",
    });
    expect(hits(dir, "insecure-file-upload").map((h) => `${h.file}:${h.line}`).sort()).toEqual(["direct.php:2", "upload.php:4"]);
  });

  it("Laravel: move() / storeAs() with getClientOriginalName() and no validation", () => {
    const bad = project({ "app/Http/Controllers/UpController.php": "<?php\nclass UpController {\n  public function store(Request $request) {\n    $file = $request->file('doc');\n    $file->move(public_path('uploads'), $file->getClientOriginalName());\n  }\n}\n" });
    expect(hits(bad, "insecure-file-upload")).toHaveLength(1);
    const good = project({ "app/Http/Controllers/UpController.php": "<?php\nclass UpController {\n  public function store(Request $request) {\n    $request->validate(['doc' => 'required|mimes:pdf,png']);\n    $file = $request->file('doc');\n    $file->move(public_path('uploads'), $file->getClientOriginalName());\n  }\n}\n" });
    expect(hits(good, "insecure-file-upload")).toHaveLength(0);
  });
});

describe("missing-security-headers", () => {
  const server = "const express = require('express');\nconst app = express();\napp.get('/', (req, res) => res.render('index'));\napp.listen(3000);\n";

  it("an Express app that sets no security header is reported once, with low severity and confidence", () => {
    const found = hits(project({ "server.js": server, "routes.js": "module.exports = (app) => app.get('/x', (req, res) => res.send('x'));\n" }), "missing-security-headers");
    expect(found).toEqual([{ file: "server.js", line: 2, confidence: "low", severity: "low" }]);
  });

  it("silent when helmet, a hand-set header or a host config sets them anywhere in the project", () => {
    expect(hits(project({ "server.js": server, "security.js": "app.use(require('helmet')());\n" }), "missing-security-headers")).toHaveLength(0);
    expect(hits(project({ "server.js": server + "app.use((req, res, next) => { res.setHeader('X-Content-Type-Options', 'nosniff'); next(); });\n" }), "missing-security-headers")).toHaveLength(0);
    expect(hits(project({ "server.js": server, "vercel.json": '{ "headers": [{ "source": "/(.*)", "headers": [{ "key": "X-Frame-Options", "value": "DENY" }] }] }' }), "missing-security-headers")).toHaveLength(0);
  });

  it("a pure JSON API is not judged (nothing for a CSP to protect)", () => {
    expect(hits(project({ "server.js": "const app = express();\napp.get('/api/x', (req, res) => res.json({ ok: true }));\napp.listen(3000);\n" }), "missing-security-headers")).toHaveLength(0);
    expect(hits(project({ "main.py": "from fastapi import FastAPI\napp = FastAPI()\n@app.get('/x')\ndef x():\n    return {'ok': True}\n" }), "missing-security-headers")).toHaveLength(0);
  });

  it("Flask is judged, a project with no web app is not, and an inline ignore works", () => {
    expect(hits(project({ "app.py": "from flask import Flask, render_template\napp = Flask(__name__)\n@app.route('/')\ndef home():\n    return render_template('home.html')\n" }), "missing-security-headers")).toHaveLength(1);
    expect(hits(project({ "util.js": "module.exports = (a) => a + 1;\n" }), "missing-security-headers")).toHaveLength(0);
    expect(hits(project({ "server.js": "// security-hub-ignore missing-security-headers -- the proxy sets them\nconst app = express();\napp.get('/', (req, res) => res.render('index'));\napp.listen(3000);\n" }), "missing-security-headers")).toHaveLength(0);
  });
});
