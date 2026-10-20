import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { fixPromptFor, scanPath, scanSource } from "../src";

jest.setTimeout(60_000);

const repo = path.resolve(__dirname, "../../..");

function found(root: string): string[] {
  const summary = scanPath(root, { config: false });
  return summary.results
    .flatMap((r) => r.findings.map((f) => `${path.relative(root, r.file).split(path.sep).join("/")}:${f.location.startLine}:${f.ruleId}`))
    .sort();
}

const py = (code: string, rule?: string, file = "/app/app.py"): string[] =>
  scanSource(code, file).findings.filter((f) => !rule || f.ruleId === rule).map((f) => f.ruleId);
const php = (code: string, rule?: string, file = "/app/index.php"): string[] =>
  scanSource(`<?php\n${code}\n`, file).findings.filter((f) => !rule || f.ruleId === rule).map((f) => f.ruleId);

describe("Python (examples/vulnerable-python-app)", () => {
  const result = found(path.join(repo, "examples", "vulnerable-python-app"));

  it("finds every planted bug in Flask, FastAPI and Django code", () => {
    expect(result).toEqual(
      expect.arrayContaining([
        "flask_app.py:19:sql-injection", // f-string into cursor.execute
        "flask_app.py:41:command-injection", // shell=True with a built string
        "flask_app.py:48:xss", // returned HTML string
        "flask_app.py:59:code-injection", // render_template_string("<p>" + x)
        "flask_app.py:64:path-traversal",
        "flask_app.py:74:insecure-deserialization", // pickle.loads
        "flask_app.py:75:insecure-deserialization", // yaml.load without a safe loader
        "flask_app.py:81:ssrf",
        "flask_app.py:86:open-redirect",
        "flask_app.py:91:code-injection", // eval
        "flask_app.py:102:sql-injection", // through a helper defined in the same file
        "flask_app.py:106:debug-mode",
        "flask_app.py:12:hardcoded-secret",
        "fastapi_app.py:20:sql-injection", // an untyped str parameter
        "fastapi_app.py:25:xss",
        "fastapi_app.py:32:command-injection",
        "django_views.py:8:sql-injection", // a URL capture is text
        "django_views.py:13:xss",
        "django_views.py:17:open-redirect",
        "django_views.py:21:csrf", // @csrf_exempt
        "settings.py:2:debug-mode",
        "settings.py:1:hardcoded-secret",
      ]),
    );
  });

  it("leaves the safe versions alone: a converted number, a bound parameter, an escaped value, secure_filename", () => {
    const lines = result.filter((r) => r.startsWith("flask_app.py")).map((r) => Number(r.split(":")[1]));
    for (const safe of [26, 33, 54, 70]) expect(lines).not.toContain(safe); // /users/<int:uid>, %s parameter, escape(), secure_filename
    expect(result.some((r) => r.startsWith("fastapi_app.py:15"))).toBe(false); // item_id: int
  });
});

describe("Python rules", () => {
  it("SQL: building the text with f-strings, %, + or .format is injection; bound parameters are not", () => {
    const head = "@app.route('/x')\ndef x():\n    q = request.args.get('q')\n    cur = db.cursor()\n";
    expect(py(`${head}    cur.execute("SELECT * FROM t WHERE a = '%s'" % q)\n`, "sql-injection")).toHaveLength(1);
    expect(py(`${head}    cur.execute("SELECT * FROM t WHERE a = '" + q + "'")\n`, "sql-injection")).toHaveLength(1);
    expect(py(`${head}    cur.execute("SELECT * FROM t WHERE a = '{}'".format(q))\n`, "sql-injection")).toHaveLength(1);
    expect(py(`${head}    session.execute(text(f"SELECT * FROM t WHERE a = '{q}'"))\n`, "sql-injection")).toHaveLength(1);
    expect(py(`${head}    cur.execute("SELECT * FROM t WHERE a = %s", (q,))\n`, "sql-injection")).toHaveLength(0);
    expect(py(`${head}    cur.execute("SELECT * FROM t WHERE a = :a", {"a": q})\n`, "sql-injection")).toHaveLength(0);
    expect(py(`${head}    cur.execute(f"SELECT * FROM t WHERE a = {int(q)}")\n`, "sql-injection")).toHaveLength(0);
    expect(py(`${head}    q = int(q)\n    cur.execute(f"SELECT * FROM t WHERE a = {q}")\n`, "sql-injection")).toHaveLength(0);
  });

  it("Django: request.GET / request.POST are input; the ORM's filter() is not a sink, raw() is", () => {
    expect(py("def v(request):\n    name = request.GET['n']\n    return list(User.objects.raw(f\"select * from u where n = '{name}'\"))\n", "sql-injection")).toHaveLength(1);
    expect(py("def v(request):\n    name = request.GET['n']\n    return list(User.objects.filter(name=name))\n", "sql-injection")).toHaveLength(0);
    expect(py("def v(request):\n    c = request.POST.get('c')\n    os.system('echo ' + c)\n", "command-injection")).toHaveLength(1);
  });

  it("FastAPI: typed numbers are converted by the framework, str and untyped parameters are not", () => {
    const route = (type: string): string => `@app.get('/i')\ndef i(v${type}):\n    db.execute(f"select * from t where a = {v}")\n`;
    expect(py(route(": int"), "sql-injection")).toHaveLength(0);
    expect(py(route(": Optional[int] = None"), "sql-injection")).toHaveLength(0);
    expect(py(route(": UUID"), "sql-injection")).toHaveLength(0);
    expect(py(route(": str"), "sql-injection")).toHaveLength(1);
    expect(py(route(""), "sql-injection")).toHaveLength(1);
    expect(py("@app.get('/i')\ndef i(v: str, db=Depends(get_db)):\n    db.execute('select 1')\n", "sql-injection")).toHaveLength(0);
  });

  it("subprocess is only a shell hole with shell=True; yaml.safe_load and a SafeLoader are fine", () => {
    const head = "@app.route('/x')\ndef x():\n    c = request.args['c']\n";
    expect(py(`${head}    subprocess.run("ls " + c, shell=True)\n`, "command-injection")).toHaveLength(1);
    expect(py(`${head}    subprocess.run(["ls", c])\n`, "command-injection")).toHaveLength(0);
    expect(py(`${head}    yaml.safe_load(c)\n`, "insecure-deserialization")).toHaveLength(0);
    expect(py(`${head}    yaml.load(c, Loader=yaml.SafeLoader)\n`, "insecure-deserialization")).toHaveLength(0);
    expect(py(`${head}    yaml.load(c)\n`, "insecure-deserialization")).toHaveLength(1);
  });

  it("SSRF: a fixed host with a variable path is not; open redirect: a checked target is not", () => {
    expect(py("@app.route('/x')\ndef x():\n    return requests.get(f'https://api.example.com/users/{request.args[\"id\"]}').text\n", "ssrf")).toHaveLength(0);
    expect(py("@app.route('/x')\ndef x():\n    return requests.get(request.args['url']).text\n", "ssrf")).toHaveLength(1);
    const guarded = "def v(request):\n    n = request.GET['next']\n    if url_has_allowed_host_and_scheme(n, allowed_hosts={request.get_host()}):\n        return HttpResponseRedirect(n)\n";
    expect(py(guarded, "open-redirect")).toHaveLength(0);
    expect(py(guarded.replace("url_has_allowed_host_and_scheme(n, allowed_hosts={request.get_host()})", "True"), "open-redirect")).toHaveLength(1);
  });

  it("tracks a reassignment: a value cleaned later is not tainted any more, and a loop variable over input is", () => {
    expect(py("@app.route('/x')\ndef x():\n    q = request.args['q']\n    q = escape(q)\n    return f'<p>{q}</p>'\n", "xss")).toHaveLength(0);
    expect(py("@app.route('/x')\ndef x():\n    for k, v in request.form.items():\n        os.system('echo ' + v)\n", "command-injection")).toHaveLength(1);
  });

  it("debug mode, csrf_exempt, a JWT decoded without verification and secrets in the code", () => {
    expect(py("app.run(host='0.0.0.0', debug=True)\n", "debug-mode")).toHaveLength(1);
    expect(py("app.run(debug=False)\n", "debug-mode")).toHaveLength(0);
    expect(py("DEBUG = True\n", "debug-mode", "/app/settings.py")).toHaveLength(1);
    expect(py("DEBUG = os.environ.get('DEBUG') == '1'\n", "debug-mode", "/app/settings.py")).toHaveLength(0);
    expect(py("data = jwt.decode(token, options={'verify_signature': False})\n", "insecure-jwt")).toHaveLength(1);
    expect(py("data = jwt.decode(token, SECRET, algorithms=['HS256'])\n", "insecure-jwt")).toHaveLength(0);
    expect(py("SECRET_KEY = 'Zk3!p9Lq7#vX2mRt5Nb8'\n", "hardcoded-secret")).toHaveLength(1);
    expect(py("SECRET_KEY = os.environ['SECRET_KEY']\nPASSWORD = 'changeme'\n", "hardcoded-secret")).toHaveLength(0);
    expect(py("db = connect(password='Zk3!p9Lq7#vX2mRt5Nb8')\n", "hardcoded-secret")).toHaveLength(1);
  });

  it("a helper in the same file is followed one call deep, and a parameterised helper is not a finding", () => {
    const code =
      "def find(name):\n    cur.execute(\"select * from t where n = '%s'\" % name)\n\n@app.route('/x')\ndef x():\n    return find(request.args['n'])\n";
    expect(py(code, "sql-injection").length).toBeGreaterThan(0);
    const safe = "def find(name):\n    cur.execute('select * from t where n = %s', (name,))\n\n@app.route('/x')\ndef x():\n    return find(request.args['n'])\n";
    expect(py(safe, "sql-injection")).toHaveLength(0);
  });
});

describe("PHP (examples/vulnerable-php-app)", () => {
  const result = found(path.join(repo, "examples", "vulnerable-php-app"));

  it("finds every planted bug in a plain script and a Laravel controller", () => {
    expect(result).toEqual(
      expect.arrayContaining([
        "index.php:7:sql-injection",
        "index.php:19:xss",
        "index.php:25:command-injection",
        "index.php:28:code-injection", // include $_GET['page']
        "index.php:31:path-traversal",
        "index.php:34:insecure-deserialization",
        "index.php:37:open-redirect",
        "index.php:40:code-injection", // eval
        "index.php:43:ssrf",
        "index.php:46:debug-mode",
        "index.php:49:hardcoded-secret",
        "index.php:55:sql-injection", // through the lookup() helper
        "UserController.php:12:sql-injection", // a route parameter
        "UserController.php:22:mass-assignment",
        "UserController.php:27:sql-injection", // $request->input() into whereRaw
      ]),
    );
  });

  it("leaves the safe versions alone: an int cast, a prepared statement, htmlspecialchars, an int-typed route parameter, only()", () => {
    const lines = (file: string): number[] => result.filter((r) => r.startsWith(`${file}:`)).map((r) => Number(r.split(":")[1]));
    for (const safe of [10, 14, 15, 16, 22]) expect(lines("index.php")).not.toContain(safe);
    for (const safe of [17, 32]) expect(lines("UserController.php")).not.toContain(safe);
  });
});

describe("PHP rules", () => {
  it("every superglobal is input, and $_SERVER only for the keys a caller writes", () => {
    for (const source of ["$_GET['a']", "$_POST['a']", "$_REQUEST['a']", "$_COOKIE['a']", "$_SERVER['HTTP_USER_AGENT']", "$_SERVER['QUERY_STRING']"]) {
      expect(php(`mysql_query("select " . ${source});`, "sql-injection")).toHaveLength(1);
    }
    expect(php("mysql_query(\"select \" . $_SERVER['SERVER_NAME']);", "sql-injection")).toHaveLength(0);
  });

  it("follows the value through concatenation, interpolation, sprintf and assignments; stops at casts and escaping", () => {
    expect(php("$a = $_GET['a']; $b = \"x $a\"; $c = $b . 'y'; mysqli_query($conn, $c);", "sql-injection")).toHaveLength(1);
    expect(php("$q = sprintf(\"select * from t where a = '%s'\", $_GET['a']); $pdo->query($q);", "sql-injection")).toHaveLength(1);
    expect(php("$a = intval($_GET['a']); mysqli_query($conn, \"select $a\");", "sql-injection")).toHaveLength(0);
    expect(php("$a = mysqli_real_escape_string($conn, $_GET['a']); mysqli_query($conn, \"select '$a'\");", "sql-injection")).toHaveLength(0);
    expect(php("$a = $_GET['a']; $a = (int) $a; mysqli_query($conn, \"select $a\");", "sql-injection")).toHaveLength(0);
    expect(php("foreach ($_GET as $k => $v) { system('echo ' . $v); }", "command-injection")).toHaveLength(1);
    expect(php("system('echo ' . escapeshellarg($_GET['a']));", "command-injection")).toHaveLength(0);
  });

  it("echo, print and the short echo tag", () => {
    expect(php("print $_GET['a'];", "xss")).toHaveLength(1);
    expect(php("echo htmlspecialchars($_GET['a']);", "xss")).toHaveLength(0);
    expect(php("echo 'static';", "xss")).toHaveLength(0);
    expect(scanSource("<p><?= $_GET['a'] ?></p>", "/app/page.php").findings.some((f) => f.ruleId === "xss")).toBe(true);
  });

  it("Laravel: $request->input() is input; a bound value and validated() are not holes", () => {
    const controller = (body: string): string => `class C extends Controller { public function a(Request $request) { ${body} } }`;
    expect(php(controller("return DB::select(\"select * from t where a = '\" . $request->input('a') . \"'\");"), "sql-injection")).toHaveLength(1);
    expect(php(controller("return DB::select('select * from t where a = ?', [$request->input('a')]);"), "sql-injection")).toHaveLength(0);
    expect(php(controller("return User::create($request->all());"), "mass-assignment")).toHaveLength(1);
    expect(php(controller("return User::create($request->validated());"), "mass-assignment")).toHaveLength(0);
  });

  it("file_get_contents of a URL with a fixed host is not a path hole; of a request value it is", () => {
    expect(php("echo file_get_contents('https://api.example.com/v1/' . $_GET['id']);", "path-traversal")).toHaveLength(0);
    expect(php("echo file_get_contents($_GET['f']);", "path-traversal")).toHaveLength(1);
    expect(php("echo file_get_contents(basename($_GET['f']));", "path-traversal")).toHaveLength(0);
  });
});

describe("Python and PHP in a project scan", () => {
  it("scans .py and .php, skips tests and virtual environments, and keeps the JavaScript rules off them", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "hub-py-"));
    const write = (name: string, text: string): void => {
      fs.mkdirSync(path.dirname(path.join(dir, name)), { recursive: true });
      fs.writeFileSync(path.join(dir, name), text);
    };
    const bug = "@app.route('/x')\ndef x():\n    os.system('echo ' + request.args['a'])\n";
    write("app.py", bug);
    write("test_app.py", bug);
    write("tests/test_other.py", bug);
    write("conftest.py", bug);
    write("venv/lib/site.py", bug);
    write("lib/Thing.php", "<?php system($_GET['c']);");
    write("lib/ThingTest.php", "<?php system($_GET['c']);");
    write("app.js", "app.get('/x', (req, res) => { exec('echo ' + req.query.a); });");
    const files = scanPath(dir, { config: false }).results.map((r) => path.relative(dir, r.file).split(path.sep).join("/")).sort();
    expect(files).toEqual(["app.js", "app.py", "lib/Thing.php"]);
    expect(scanPath(dir, { config: false, includeTests: true }).results.length).toBeGreaterThan(3);
  });

  it("a hostile file (a very deep expression, thousands of calls) neither crashes nor hangs", () => {
    const deepPy = `x = ${"1+".repeat(40000)}1\n`;
    const manyPy = `def f(a):\n${"    execute('x' + a)\n".repeat(3000)}`;
    const deepPhp = `<?php $x = ${"1+".repeat(40000)}1;`;
    const started = Date.now();
    expect(scanSource(deepPy, "/a/deep.py").findings).toEqual([]);
    expect(Array.isArray(scanSource(manyPy, "/a/many.py").findings)).toBe(true);
    expect(scanSource(deepPhp, "/a/deep.php").findings).toEqual([]);
    expect(Date.now() - started).toBeLessThan(40_000);
  });

  it("the fix prompt gives Python and PHP advice, not JavaScript advice", () => {
    const finding = scanSource("@app.route('/x')\ndef x():\n    cur.execute(f\"select {request.args['a']}\")\n", "/app/a.py").findings[0];
    expect(finding).toBeDefined();
    expect(fixPromptFor(finding as NonNullable<typeof finding>)).toContain("cursor.execute(");
    expect(fixPromptFor(finding as NonNullable<typeof finding>)).not.toContain("db.query(");
    const phpFinding = scanSource("<?php mysql_query('select ' . $_GET['a']);", "/app/a.php").findings[0];
    expect(phpFinding).toBeDefined();
    expect(fixPromptFor(phpFinding as NonNullable<typeof phpFinding>)).toContain("prepare(");
  });
});

describe("Python and PHP precision fixes (validation round 12)", () => {
  it("a redirect that starts with a path of this site is not an open redirect", () => {
    const view = (target: string): string => `def v(request):\n    item = request.GET['id']\n    return redirect(${target})\n`;
    expect(py(view("f\"{reverse('home')}?open={item}\""), "open-redirect")).toHaveLength(0);
    expect(py(view("'/items/' + item"), "open-redirect")).toHaveLength(0);
    expect(py(view("item"), "open-redirect")).toHaveLength(1);
    expect(py(view("'//' + item"), "open-redirect")).toHaveLength(1);
    expect(php("header('Location: /items/' . $_GET['id']);", "open-redirect")).toHaveLength(0);
    expect(php("header('Location: ' . $_GET['u']);", "open-redirect")).toHaveLength(1);
  });

  it("$_FILES: the path PHP chose and the size are not the caller's, the file name is", () => {
    expect(php("$p = $_FILES['f']['tmp_name']; echo file_get_contents($p);", "path-traversal")).toHaveLength(0);
    expect(php("echo file_get_contents($_FILES['f']['name']);", "path-traversal")).toHaveLength(1);
  });

  it("Laravel validation rules, seeders and Django's tests.py are not credentials", () => {
    expect(php("$rules = ['password' => 'required|string|min:8|confirmed'];", "hardcoded-secret")).toHaveLength(0);
    expect(php("$u = ['password' => 'Zk3!p9Lq7#vX2mRt5Nb8'];", "hardcoded-secret")).toHaveLength(1);
    expect(php("class DemoSeeder { const DEMO_PASSWORD = 'Zk3!p9Lq7#vX2mRt5Nb8'; }", "hardcoded-secret", "/app/database/seeders/DemoSeeder.php")).toHaveLength(0);
    expect(py("PASSWORD = 'Zk3!p9Lq7#vX2mRt5Nb8'\n", "hardcoded-secret", "/app/screening/tests.py")).toHaveLength(1); // scanSource does not skip tests: the walk does
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "hub-tests-py-"));
    fs.writeFileSync(path.join(dir, "tests.py"), "PASSWORD = 'Zk3!p9Lq7#vX2mRt5Nb8'\n");
    fs.writeFileSync(path.join(dir, "views.py"), "PASSWORD = 'Zk3!p9Lq7#vX2mRt5Nb8'\n");
    expect(scanPath(dir, { config: false }).results.map((r) => path.basename(r.file))).toEqual(["views.py"]);
  });

  it("a minified or bundled file is skipped with a note, not analysed for 15 seconds", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "hub-min-"));
    fs.writeFileSync(path.join(dir, "bundle.js"), `var a=${"x+1;".repeat(20000)}`); // one 80 KB line
    fs.writeFileSync(path.join(dir, "app.js"), "app.get('/x', (req, res) => { exec('echo ' + req.query.a); });\n");
    const results = scanPath(dir, { config: false }).results;
    const bundle = results.find((r) => r.file.endsWith("bundle.js"));
    expect(bundle?.parseError).toMatch(/minified or bundled/);
    expect(results.find((r) => r.file.endsWith("app.js"))?.findings.length).toBeGreaterThan(0);
  });
});

describe("development settings files", () => {
  it("DEBUG = True is reported in settings.py but not in settings/dev.py or a tests settings file", () => {
    expect(py("DEBUG = True\n", "debug-mode", "/app/proj/settings.py")).toHaveLength(1);
    expect(py("DEBUG = True\n", "debug-mode", "/app/config/settings/dev.py")).toHaveLength(0);
    expect(py("DEBUG = True\n", "debug-mode", "/app/proj_tests/settings.py")).toHaveLength(0);
    // a project that merely lives in a folder called "test" is not a test settings file
    expect(py("DEBUG = True\n", "debug-mode", "/home/me/test/shop/proj/settings.py")).toHaveLength(1);
  });
});

describe("data flow across files (validation round 12, improvement 1)", () => {
  const python = found(path.join(repo, "examples", "vulnerable-python-app"));
  const phpFound = found(path.join(repo, "examples", "vulnerable-php-app"));

  it("Python: a view calling a helper in another module (from-import, module alias, an imported class's method, two hops)", () => {
    expect(python).toEqual(
      expect.arrayContaining([
        "app/routes.py:12:sql-injection", // from .db import find_user
        "app/routes.py:17:sql-injection", // from . import db as database; database.find_user(...)
        "app/routes.py:27:command-injection", // report_for -> run_report -> subprocess (shell=True)
        "app/routes.py:32:sql-injection", // UserService().lookup -> find_user
      ]),
    );
    expect(python.some((r) => r.startsWith("app/routes.py:22:"))).toBe(false); // find_user_safe binds the value
    expect(python.some((r) => r.startsWith("app/db.py") && /sql-injection|command/.test(r))).toBe(false); // the helper alone is not a handler
  });

  it("PHP: a global function in another file, a static method, an injected service, two hops", () => {
    expect(phpFound).toEqual(
      expect.arrayContaining([
        "search.php:4:sql-injection", // find_user_by_name() in lib/db.php
        "search.php:6:command-injection", // report_for -> run_report -> shell_exec
        "app/Http/Controllers/SearchController.php:15:sql-injection", // $this->users->search(...)
        "app/Http/Controllers/SearchController.php:20:sql-injection", // UserRepository::findBy(...)
      ]),
    );
    expect(phpFound.some((r) => r.startsWith("search.php:5:"))).toBe(false); // find_user_safe prepares the statement
  });

  it("the finding says where the value ends up, and cyclic calls do not loop", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "hub-xfile-"));
    const write = (name: string, text: string): void => {
      fs.mkdirSync(path.dirname(path.join(dir, name)), { recursive: true });
      fs.writeFileSync(path.join(dir, name), text);
    };
    write("pkg/__init__.py", "");
    write("pkg/a.py", "from .b import second\n\ndef first(x, n):\n    if n:\n        return second(x, n - 1)\n    return x\n");
    write("pkg/b.py", "import os\nfrom .a import first\n\ndef second(x, n):\n    os.system('echo ' + x)\n    return first(x, n)\n");
    write("views.py", "from flask import request\nfrom pkg.a import first\n\n@app.route('/x')\ndef x():\n    return first(request.args['v'], 3)\n");
    const result = scanPath(dir, { config: false });
    const finding = result.results.flatMap((r) => r.findings).find((f) => f.ruleId === "command-injection");
    expect(finding?.message).toContain("pkg/b.py:5");
    expect(finding?.message).toContain("via second");
  });
});

describe("checks clear the value (validation round 12, improvement 2)", () => {
  const route = (body: string): string => `@app.route('/x')\ndef x():\n    v = request.args['v']\n    cur = db.cursor()\n${body}`;

  it("Python: inside the branch a check guards, and after a failed check that stops the function", () => {
    expect(py(route("    if v.isdigit():\n        cur.execute(f\"select {v}\")\n"), "sql-injection")).toHaveLength(0);
    expect(py(route("    if v.isdigit():\n        pass\n    cur.execute(f\"select {v}\")\n"), "sql-injection")).toHaveLength(1); // after the if: not checked
    expect(py(route("    if not v.isdigit():\n        abort(400)\n    cur.execute(f\"select {v}\")\n"), "sql-injection")).toHaveLength(0);
    expect(py(route("    if not v.isdigit():\n        return 'bad'\n    cur.execute(f\"select {v}\")\n"), "sql-injection")).toHaveLength(0);
    expect(py(route("    if not v.isdigit():\n        print('hm')\n    cur.execute(f\"select {v}\")\n"), "sql-injection")).toHaveLength(1); // the failed check does not stop anything
    expect(py(route("    if v in ('a', 'b'):\n        cur.execute(f\"select {v}\")\n"), "sql-injection")).toHaveLength(0);
    expect(py(route("    if v in ALLOWED and other:\n        cur.execute(f\"select {v}\")\n"), "sql-injection")).toHaveLength(0);
    expect(py(route("    if v in ALLOWED or other:\n        cur.execute(f\"select {v}\")\n"), "sql-injection")).toHaveLength(1); // `or`: the first part may be false
    expect(py(route("    if re.fullmatch(r'[a-z]+', v):\n        cur.execute(f\"select {v}\")\n"), "sql-injection")).toHaveLength(0);
    expect(py(route("    if is_valid_name(v):\n        cur.execute(f\"select {v}\")\n"), "sql-injection")).toHaveLength(0);
    expect(py(route("    if v.startswith('a'):\n        cur.execute(f\"select {v}\")\n"), "sql-injection")).toHaveLength(1); // says nothing about the rest of the value
    expect(py(route("    if v == 'admin':\n        cur.execute(f\"select {v}\")\n    else:\n        cur.execute(f\"select {v}\")\n"), "sql-injection")).toHaveLength(1);
  });

  it("PHP: is_numeric, in_array and an anchored preg_match, inside the branch and as an early exit", () => {
    expect(php("$id = $_GET['id']; if (is_numeric($id)) { mysql_query(\"select $id\"); }", "sql-injection")).toHaveLength(0);
    expect(php("$id = $_GET['id']; if (is_numeric($id)) { } mysql_query(\"select $id\");", "sql-injection")).toHaveLength(1);
    expect(php("$id = $_GET['id']; if (!is_numeric($id)) { exit; } mysql_query(\"select $id\");", "sql-injection")).toHaveLength(0);
    expect(php("$id = $_GET['id']; if (!is_numeric($id)) { die('bad'); } mysql_query(\"select $id\");", "sql-injection")).toHaveLength(0);
    expect(php("$id = $_GET['id']; if (!is_numeric($id)) { echo 'x'; } mysql_query(\"select $id\");", "sql-injection")).toHaveLength(1);
    expect(php("$p = $_GET['p']; if (in_array($p, $allowed)) { include $p . '.php'; }", "code-injection")).toHaveLength(0);
    expect(php("$p = $_GET['p']; if (!preg_match('/^[a-z]+$/', $p)) { die('bad'); } include $p;", "code-injection")).toHaveLength(0);
    expect(php("$p = $_GET['p']; if (preg_match('/^[a-z]/', $p)) { include $p; }", "code-injection")).toHaveLength(1); // not anchored at the end
    expect(php("$p = $_GET['p']; if (strlen($p) > 3) { include $p; }", "code-injection")).toHaveLength(1);
    expect(php("$p = $_GET['p']; if ($p === 'home') { include $p; }", "code-injection")).toHaveLength(0);
  });

  it("checking that a key EXISTS says nothing about its value", () => {
    expect(php("$input = json_decode(file_get_contents('php://input'), true); if (array_key_exists('target', $input)) { $t = $input['target']; exec('ping ' . $t); }", "command-injection")).toHaveLength(1);
  });

  it("DVWA's 'impossible' level: the address is checked with is_numeric before it reaches the shell", () => {
    const code =
      "$target = stripslashes($_REQUEST['ip']);\n$octet = explode('.', $target);\nif ((is_numeric($octet[0])) && (is_numeric($octet[1]))) {\n    $target = $octet[0] . '.' . $octet[1];\n    $cmd = shell_exec('ping ' . $target);\n}\n";
    expect(php(code, "command-injection")).toHaveLength(0); // the check names $octet[0]: the list of octets counts as checked
    const simple = "$ip = $_REQUEST['ip'];\nif (is_numeric($ip)) {\n    $cmd = shell_exec('ping ' . $ip);\n}\n";
    expect(php(simple, "command-injection")).toHaveLength(0);
  });
});

describe("templates and the remaining rules (validation round 12, improvements 3 and 4)", () => {
  const python = found(path.join(repo, "examples", "vulnerable-python-app"));
  const phpFound = found(path.join(repo, "examples", "vulnerable-php-app"));

  it("a value handed to a template that prints it unescaped is XSS: Jinja |safe and Blade {!! !!}; the escaped variable next to it is not", () => {
    expect(python).toContain("templates_app.py:8:xss");
    expect(python.filter((r) => r.startsWith("templates_app.py"))).toHaveLength(1); // `title` is printed by {{ title }}
    expect(phpFound).toContain("app/Http/Controllers/ProfileController.php:10:xss");
    expect(phpFound.filter((r) => r.startsWith("app/Http/Controllers/ProfileController.php"))).toHaveLength(1); // $bio is escaped
  });

  it("templates are found by name in a project's folders, autoescape off counts, a template elsewhere is not guessed", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "hub-tpl-"));
    const write = (name: string, text: string): void => {
      fs.mkdirSync(path.dirname(path.join(dir, name)), { recursive: true });
      fs.writeFileSync(path.join(dir, name), text);
    };
    write("shop/templates/shop/item.html", "{% autoescape off %}<p>{{ desc }}</p>{% endautoescape %}<p>{{ name }}</p>");
    write("views.py", "def item(request):\n    return render(request, 'shop/item.html', {'desc': request.GET['d'], 'name': request.GET['n']})\n");
    write("other.py", "def other(request):\n    return render(request, 'missing.html', {'desc': request.GET['d']})\n");
    const result = scanPath(dir, { config: false });
    const xss = result.results.flatMap((r) => r.findings.map((f) => `${path.basename(r.file)}:${f.ruleId}:${f.message.includes("autoescape off")}`)).filter((x) => x.includes(":xss:"));
    expect(xss).toEqual(["views.py:xss:true"]); // desc yes, name no, the unknown template nothing
  });

  it("Python mass assignment: the whole body into a write, not a single field or a validated form", () => {
    const hits = (code: string): number => scanSource(code, "/app/v.py").findings.filter((f) => f.ruleId === "mass-assignment").length;
    expect(hits("def v(request):\n    return User.objects.create(**request.POST.dict())\n")).toBe(1);
    expect(hits("@app.route('/s')\ndef s():\n    data = request.get_json()\n    db.session.add(User(**data))\n")).toBe(1);
    expect(hits("@app.route('/s')\ndef s():\n    db.users.insert_one(request.get_json())\n")).toBe(1);
    expect(hits("@app.route('/s')\ndef s():\n    return User(name=request.json['name'])\n")).toBe(0);
    expect(hits("def v(request):\n    form = F(request.POST)\n    if form.is_valid():\n        return User.objects.create(**form.cleaned_data)\n")).toBe(0);
  });

  it("PHP: a JWT that accepts the none algorithm or is read without verification, and CSRF protection switched off", () => {
    const rules = (code: string, file = "/app/a.php"): string[] => scanSource(`<?php\n${code}\n`, file).findings.map((f) => f.ruleId);
    expect(rules("$d = JWT::decode($tok, $key, ['HS256', 'none']);")).toContain("insecure-jwt");
    expect(rules("$d = JWT::decode($tok, new Key($key, 'HS256'));")).not.toContain("insecure-jwt");
    expect(rules("$p = json_decode(base64_decode(explode('.', $tok)[1]));")).toContain("insecure-jwt");
    expect(rules("class V extends VerifyCsrfToken { protected $except = ['*']; }")).toContain("csrf");
    expect(rules("class V extends VerifyCsrfToken { protected $except = ['stripe/webhook']; }")).not.toContain("csrf");
    const blade = scanSource("<form method=\"POST\" action=\"/x\"><input></form>\n<form method=\"post\">@csrf<input></form>\n", "/app/resources/views/a.blade.php").findings.filter((f) => f.ruleId === "csrf");
    expect(blade.map((f) => f.location.startLine)).toEqual([1]);
  });
});

describe("validation round 14: layered projects", () => {
  it("use_case.execute(command) runs application code, cursor.execute(query) runs SQL", () => {
    const view = (call: string): string => `@router.post("/x")\ndef x(request: Request):\n    value = request.query_params["v"]\n    ${call}\n`;
    expect(py(view("use_case.execute(value)"), "sql-injection")).toHaveLength(0);
    expect(py(view("container.import_products.execute(value)"), "sql-injection")).toHaveLength(0);
    expect(py(view("GetProfileUseCase(service).execute(value)"), "sql-injection")).toHaveLength(0);
    expect(py(view("cursor.execute(value)"), "sql-injection")).toHaveLength(1);
    expect(py(view("db.session.execute(value)"), "sql-injection")).toHaveLength(1);
    expect(py(view("handler.execute(f\"SELECT * FROM t WHERE a = {value}\")"), "sql-injection")).toHaveLength(1);
  });
  it("a redirect whose host comes from configuration is not an open redirect", () => {
    const view = (target: string): string => `def v(request, path):
    base = getattr(settings, 'X', '')
    return redirect(${target})
`;
    expect(py(view('f"{frontend_base_url}/book/{path}"'), "open-redirect")).toHaveLength(0);
    expect(py(view('settings.SITE_URL + path'), "open-redirect")).toHaveLength(0);
    expect(py(view('path'), "open-redirect")).toHaveLength(1);
  });

  it("demo logins, placeholders and stub tokens are not leaked credentials", () => {
    expect(py('DEMO = {"email": "alice@example.com", "password": "Alice123!"}\n', "hardcoded-secret")).toHaveLength(0);
    expect(py('DEMO = {"email": "alice@company.io", "password": "Alice123!"}\n', "hardcoded-secret")).toHaveLength(1);
    expect(py('_DEV_SECRET = "dev-only-secret-for-local-runs"\n', "hardcoded-secret")).toHaveLength(0);
    expect(py('token = Token(access_token="stub-access-token-123")\n', "hardcoded-secret")).toHaveLength(0);
    expect(py('PASSWORD = "Zk3!p9Lq7#vX2mRt5Nb8"\n', "hardcoded-secret", "/app/scripts/e2e_login.py")).toHaveLength(0);
  });

});
