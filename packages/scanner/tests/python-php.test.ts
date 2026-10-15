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
