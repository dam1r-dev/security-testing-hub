import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { scanPath } from "../src";

jest.setTimeout(60_000);

function project(files: Record<string, string[]>): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "hub-go-"));
  for (const [name, lines] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(dir, name)), { recursive: true });
    fs.writeFileSync(path.join(dir, name), lines.join("\n") + "\n");
  }
  return dir;
}

function hits(dir: string, rule?: string): Array<{ rule: string; file: string; line: number; confidence: string }> {
  return scanPath(dir, { config: false }).results.flatMap((r) =>
    r.findings.filter((f) => !rule || f.ruleId === rule).map((f) => ({ rule: f.ruleId, file: path.basename(r.file), line: f.location.startLine, confidence: f.confidence })),
  );
}

/** One handler body wrapped into a net/http file. */
function handler(...body: string[]): string[] {
  return ['package main', '', 'import (', '\t"net/http"', ')', '', 'func handler(w http.ResponseWriter, r *http.Request) {', ...body.map((l) => `\t${l}`), '}'];
}

const rules = (dir: string): string[] => hits(dir).map((h) => h.rule).sort();

describe("Go: SQL injection", () => {
  it("a query built from the request with + or fmt.Sprintf", () => {
    const dir = project({
      "main.go": handler(
        'name := r.URL.Query().Get("name")',
        'q := "SELECT * FROM users WHERE name = \'" + name + "\'"',
        'db.Query(q)',
        'id := r.FormValue("id")',
        'db.Exec(fmt.Sprintf("DELETE FROM t WHERE id = %s", id))',
        'db.QueryRow("SELECT 1 WHERE x = \'" + r.PostFormValue("x") + "\'")',
      ),
    });
    expect(hits(dir, "sql-injection").map((h) => h.line)).toEqual([10, 12, 13]);
  });

  it("values passed separately, a number parsed first and a fixed query are fine", () => {
    const dir = project({
      "main.go": handler(
        'name := r.URL.Query().Get("name")',
        'db.Query("SELECT * FROM users WHERE name = $1", name)',
        'n, err := strconv.Atoi(r.FormValue("id"))',
        'if err != nil { return }',
        'db.Query(fmt.Sprintf("SELECT * FROM users WHERE id = %d", n))',
        'db.Query("SELECT * FROM users")',
      ),
    });
    expect(hits(dir, "sql-injection")).toEqual([]);
  });

  it("GORM: Where / Order / Raw built from the request", () => {
    const dir = project({
      "main.go": [
        'package main', '', 'import "github.com/gin-gonic/gin"', '',
        'func list(c *gin.Context) {',
        '\tsort := c.Query("sort")',
        '\tname := c.Query("name")',
        '\tdb.Where("name = \'" + name + "\'").Find(&users)',
        '\tdb.Order(sort).Find(&users)',
        '\tdb.Where("name = ?", name).Find(&users)',
        '\tdb.Raw("SELECT * FROM t WHERE a = " + c.Param("id")).Scan(&rows)',
        '}',
      ],
    });
    expect(hits(dir, "sql-injection").map((h) => h.line)).toEqual([8, 9, 11]);
  });

  it("a request body bound into a struct, a field of it in the query", () => {
    const dir = project({
      "main.go": [
        'package main', '', 'import "github.com/gin-gonic/gin"', '',
        'func create(c *gin.Context) {',
        '\tvar in Input',
        '\tif err := c.ShouldBindJSON(&in); err != nil { return }',
        '\tdb.Exec("INSERT INTO t (name) VALUES (\'" + in.Name + "\')")',
        '}',
      ],
    });
    expect(hits(dir, "sql-injection").map((h) => h.line)).toEqual([8]);
  });
});

describe("Go: commands, files, requests, redirects", () => {
  it("exec.Command through a shell, or with the program from the request", () => {
    const dir = project({
      "main.go": handler(
        'host := r.URL.Query().Get("host")',
        'exec.Command("sh", "-c", "ping -c 1 "+host).Run()',
        'exec.Command(host).Run()',
        'exec.Command("ping", "-c", "1", host).Run()',
        'exec.Command("ls", "-l").Run()',
      ),
    });
    expect(hits(dir, "command-injection").map((h) => h.line)).toEqual([9, 10]);
  });

  it("file paths: opened as sent, safe with a base name", () => {
    const dir = project({
      "main.go": handler(
        'f := r.URL.Query().Get("file")',
        'data, _ := os.ReadFile("uploads/" + f)',
        'http.ServeFile(w, r, f)',
        '_ = data',
      ),
      "safe.go": handler(
        'f := filepath.Base(r.URL.Query().Get("file"))',
        'os.ReadFile("uploads/" + f)',
      ),
    });
    expect(hits(dir, "path-traversal").map((h) => `${h.file}:${h.line}`)).toEqual(["main.go:9", "main.go:10"]);
  });

  it("outgoing requests: the URL from the request is SSRF, a fixed host is not", () => {
    const dir = project({
      "main.go": handler(
        'target := r.URL.Query().Get("url")',
        'http.Get(target)',
        'http.Get("https://api.example.com/users/" + r.URL.Query().Get("id"))',
        'client.Get(r.FormValue("u"))',
        'req, _ := http.NewRequest("GET", target, nil)',
        '_ = req',
      ),
    });
    expect(hits(dir, "ssrf").map((h) => h.line)).toEqual([9, 11, 12]);
  });

  it("redirects: to an address from the request, but not to a path of this site", () => {
    const dir = project({
      "main.go": handler(
        'http.Redirect(w, r, r.URL.Query().Get("next"), http.StatusFound)',
        'http.Redirect(w, r, "/items/"+r.URL.Query().Get("id"), http.StatusFound)',
      ),
      "gin.go": [
        'package main', '', 'import "github.com/gin-gonic/gin"', '',
        'func login(c *gin.Context) {',
        '\tc.Redirect(302, c.Query("to"))',
        '}',
      ],
    });
    expect(hits(dir, "open-redirect").map((h) => `${h.file}:${h.line}`).sort()).toEqual(["gin.go:6", "main.go:8"]);
  });
});

describe("Go: HTML in the response and templates", () => {
  it("fmt.Fprintf and w.Write of the request, template.HTML of it", () => {
    const dir = project({
      "main.go": handler(
        'name := r.URL.Query().Get("name")',
        'fmt.Fprintf(w, "<h1>Hello %s</h1>", name)',
        'w.Write([]byte("<p>" + name + "</p>"))',
        'tmpl.Execute(w, map[string]interface{}{"Bio": template.HTML(name)})',
        'fmt.Fprintf(w, "<h1>%s</h1>", html.EscapeString(name))',
      ),
    });
    expect(hits(dir, "xss").map((h) => h.line)).toEqual([9, 10, 11]);
  });

  it("a JSON reply is not HTML", () => {
    const dir = project({
      "main.go": handler(
        'w.Header().Set("Content-Type", "application/json")',
        'name := r.URL.Query().Get("name")',
        'fmt.Fprintf(w, "{\\"name\\": \\"%s\\"}", name)',
      ),
    });
    expect(hits(dir, "xss")).toEqual([]);
  });

  it("a template parsed from the request is code injection", () => {
    const dir = project({
      "main.go": handler('t, _ := template.New("x").Parse(r.FormValue("tpl"))', '_ = t'),
    });
    expect(hits(dir, "code-injection").length).toBe(1);
  });
});

describe("Go: handlers written inline, frameworks", () => {
  it("a function literal registered with HandleFunc is read once", () => {
    const dir = project({
      "main.go": [
        'package main', '', 'import "net/http"', '',
        'func main() {',
        '\thttp.HandleFunc("/x", func(w http.ResponseWriter, r *http.Request) {',
        '\t\tdb.Query("SELECT * FROM t WHERE a = \'" + r.URL.Query().Get("a") + "\'")',
        '\t})',
        '}',
      ],
    });
    expect(hits(dir, "sql-injection").map((h) => h.line)).toEqual([7]);
  });

  it("echo and fiber contexts", () => {
    const dir = project({
      "echo.go": [
        'package main', '', 'import "github.com/labstack/echo/v4"', '',
        'func get(c echo.Context) error {',
        '\tid := c.Param("id")',
        '\trows, _ := db.Query("SELECT * FROM t WHERE id = " + id)',
        '\t_ = rows',
        '\treturn c.Redirect(302, c.QueryParam("to"))',
        '}',
      ],
      "fiber.go": [
        'package main', '', 'import "github.com/gofiber/fiber/v2"', '',
        'func get(c *fiber.Ctx) error {',
        '\tdb.Exec("DELETE FROM t WHERE id = " + c.Params("id"))',
        '\treturn nil',
        '}',
      ],
    });
    expect(hits(dir).map((h) => `${h.file}:${h.line}:${h.rule}`).sort()).toEqual(["echo.go:7:sql-injection", "echo.go:9:open-redirect", "fiber.go:6:sql-injection"]);
  });

  it("chi and gorilla/mux route parameters", () => {
    const dir = project({
      "main.go": handler(
        'id := chi.URLParam(r, "id")',
        'db.Query("SELECT * FROM t WHERE id = " + id)',
        'vars := mux.Vars(r)',
        'db.Query("SELECT * FROM t WHERE name = \'" + vars["name"] + "\'")',
      ),
    });
    expect(hits(dir, "sql-injection").map((h) => h.line)).toEqual([9, 11]);
  });
});

describe("Go: helpers in other files", () => {
  it("the query is built in the repository package", () => {
    const dir = project({
      "handlers/user.go": [
        'package handlers', '', 'import "net/http"', '',
        'func Show(w http.ResponseWriter, r *http.Request) {',
        '\tuser := repo.FindUserByName(r.URL.Query().Get("name"))',
        '\t_ = user',
        '}',
      ],
      "repo/repo.go": [
        'package repo', '',
        'func FindUserByName(name string) *User {',
        '\trows, _ := db.Query("SELECT * FROM users WHERE name = \'" + name + "\'")',
        '\t_ = rows',
        '\treturn nil',
        '}',
      ],
    });
    const found = hits(dir, "sql-injection");
    expect(found.map((h) => `${h.file}:${h.line}`)).toEqual(["user.go:6"]);
  });

  it("two functions with one name are not guessed between", () => {
    const dir = project({
      "a/a.go": ['package a', '', 'func Lookup(name string) { db.Query("SELECT x FROM t WHERE n = \'" + name + "\'") }'],
      "b/b.go": ['package b', '', 'func Lookup(name string) { cache.Query(name) }'],
      "h/h.go": ['package h', '', 'import "net/http"', '', 'func Show(w http.ResponseWriter, r *http.Request) {', '\tLookup(r.URL.Query().Get("n"))', '}'],
    });
    expect(hits(dir, "sql-injection")).toEqual([]);
  });
});

describe("Go: patterns without data flow", () => {
  it("weak hashes, math/rand tokens, bcrypt cost, DES", () => {
    const dir = project({
      "main.go": [
        'package main', '',
        'import (', '\t"crypto/md5"', '\t"crypto/des"', '\t"math/rand"', '\t"golang.org/x/crypto/bcrypt"', ')', '',
        'func hashPassword(password string) []byte {',
        '\tsum := md5.Sum([]byte(password))',
        '\treturn sum[:]',
        '}',
        'func makeToken() int {',
        '\ttoken := rand.Int()',
        '\treturn token',
        '}',
        'func slow(p []byte) { bcrypt.GenerateFromPassword(p, 4); des.NewCipher(nil) }',
        'func fine(p []byte) { bcrypt.GenerateFromPassword(p, 12); n := rand.Intn(6); _ = n }',
      ],
    });
    expect(hits(dir, "weak-crypto").map((h) => h.line)).toEqual([11, 15, 18, 18]);
  });

  it("certificate checks, login cookies, pprof, unsigned JWT, CORS with credentials", () => {
    const dir = project({
      "main.go": [
        'package main', '',
        'import (', '\t"crypto/tls"', '\t"net/http"', '\t_ "net/http/pprof"', ')', '',
        'func setup(w http.ResponseWriter) {',
        '\t_ = &tls.Config{InsecureSkipVerify: true}',
        '\thttp.SetCookie(w, &http.Cookie{Name: "session", Value: "x"})',
        '\thttp.SetCookie(w, &http.Cookie{Name: "session", Value: "x", HttpOnly: true, Secure: true})',
        '\tjwt.ParseUnverified(tok, claims)',
        '\t_ = cors.Config{AllowAllOrigins: true, AllowCredentials: true}',
        '}',
      ],
    });
    const found = hits(dir).map((h) => `${h.rule}:${h.line}`).sort();
    expect(found).toEqual(["debug-endpoint:6", "insecure-cookie:11", "insecure-cors:14", "insecure-jwt:13", "tls-verification:10"]);
  });

  it("a signing secret written in the code, a value from the environment is fine", () => {
    const dir = project({
      "main.go": [
        'package main', '', 'import "os"', '',
        'var jwtSecret = []byte("hunter2hunter2")',
        'var fromEnv = os.Getenv("JWT_SECRET")',
        'var title = "Welcome to the shop"',
      ],
    });
    expect(hits(dir, "hardcoded-secret").map((h) => h.line)).toEqual([5]);
  });
});

describe("Go: precision (found on real projects)", () => {
  it("a struct condition and a prepared statement's arguments are not SQL text", () => {
    const dir = project({
      "main.go": handler(
        'user := User{Name: r.FormValue("name")}',
        'db.Where(&User{Username: r.FormValue("u")}).First(&user)',
        'stmt, _ := db.Prepare("SELECT id FROM users WHERE name = ?")',
        'stmt.Query(r.FormValue("name"))',
      ),
    });
    expect(hits(dir, "sql-injection")).toEqual([]);
  });

  it("a redirect is judged by who controls the start of the address", () => {
    const dir = project({
      "main.go": handler(
        'http.Redirect(w, r, baseURL+"/campaigns?tab="+r.FormValue("tab"), 302)',
        'http.Redirect(w, r, fmt.Sprintf("%s/campaigns/%d#tab=%s", adminURL, 1, r.FormValue("tab")), 302)',
        'http.Redirect(w, r, "https://example.com/login?next="+r.FormValue("next"), 302)',
        'http.Redirect(w, r, r.FormValue("next"), 302)',
        'http.Redirect(w, r, "//"+r.FormValue("host"), 302)',
      ),
    });
    expect(hits(dir, "open-redirect").map((h) => h.line)).toEqual([11, 12]);
  });

  it("a redirect that checks the target against a list of trusted addresses is left alone", () => {
    const dir = project({
      "main.go": handler(
        'next := r.FormValue("next")',
        'for _, d := range cfg.TrustedURLs {',
        '  if next == d { http.Redirect(w, r, next, 303) }',
        '}',
      ),
    });
    expect(hits(dir, "open-redirect")).toEqual([]);
  });

  it("the request line (a path) cannot choose the host of an outgoing request", () => {
    const dir = project({
      "main.go": handler(
        'u := fmt.Sprintf("%s://%s%s", "http", "0.0.0.0", r.RequestURI)',
        'u = strings.ReplaceAll(u, "/api", "")',
        'http.NewRequest(r.Method, u, nil)',
        'http.Get(r.FormValue("url"))',
      ),
    });
    expect(hits(dir, "ssrf").map((h) => h.line)).toEqual([11]);
  });

  it("cookies that are sent, cleared or not logins are not findings", () => {
    const dir = project({
      "main.go": handler(
        'req.AddCookie(&http.Cookie{Name: "session", Value: tok})',
        'http.SetCookie(w, &http.Cookie{Name: "session", Value: "", MaxAge: -1})',
        'http.SetCookie(w, &http.Cookie{Name: "theme", Value: "dark"})',
        'http.SetCookie(w, &http.Cookie{Name: "session", Value: tok})',
      ),
    });
    expect(hits(dir, "insecure-cookie").map((h) => h.line)).toEqual([11]);
  });

  it("a certificate check that someone switches off by an option is reported with low confidence", () => {
    const dir = project({
      "main.go": [
        'package main', '', 'import "crypto/tls"', '',
        'func plain() *tls.Config { return &tls.Config{InsecureSkipVerify: true} }',
        'func opt(skip bool) *tls.Config {',
        '\tif skip {',
        '\t\treturn &tls.Config{InsecureSkipVerify: true}',
        '\t}',
        '\treturn nil',
        '}',
      ],
    });
    expect(hits(dir, "tls-verification").map((h) => `${h.line}:${h.confidence}`)).toEqual(["5:medium", "8:low"]);
  });

  it("secrets: comments, example URLs and the NAME of an environment variable are not credentials", () => {
    const dir = project({
      "main.go": [
        'package main', '',
        '// The redis URL can include credentials, e.g. redis://user:pass@host:6379',
        'const EnvClientSecret = "APP_CLIENT_SECRET"',
        'var cache = getEnv("CACHE_URL", "redis://guest:guest@localhost:6379/")',
        'var signingKey = []byte("real-signing-material-9f3a")',
      ],
    });
    expect(hits(dir, "hardcoded-secret").map((h) => h.line)).toEqual([6]);
  });
});

describe("Go: examples/vulnerable-go-app", () => {
  const dir = path.join(__dirname, "..", "..", "..", "examples", "vulnerable-go-app");
  const found = hits(dir);

  it("finds each planted flaw, once", () => {
    const counts: Record<string, number> = {};
    for (const h of found) counts[h.rule] = (counts[h.rule] ?? 0) + 1;
    expect(counts).toEqual({
      "sql-injection": 5, "command-injection": 1, "path-traversal": 2, ssrf: 1, "open-redirect": 2, xss: 2, "insecure-cors": 1,
      "weak-crypto": 1, "insecure-cookie": 1, "tls-verification": 1, "hardcoded-secret": 1,
    });
  });

  it("follows the value into the store package, and leaves the safe handlers alone", () => {
    const main = found.filter((h) => h.file === "main.go").map((h) => h.line);
    expect(main).toContain(95); // findUser: store.FindUserByEmail(r.FormValue("email"))
    expect(main).not.toContain(44); // searchSafe: the value is passed as a parameter
    expect(found.filter((h) => h.file === "gin_app.go" && h.line >= 52 && h.line <= 58)).toEqual([]); // getPost: Atoi first
  });
});

describe("Go: what is left out", () => {
  it("tests and vendored code are not scanned", () => {
    const dir = project({
      "main_test.go": handler('db.Query("SELECT * FROM t WHERE a = \'" + r.URL.Query().Get("a") + "\'")'),
      "vendor/lib/lib.go": handler('db.Query("SELECT * FROM t WHERE a = \'" + r.URL.Query().Get("a") + "\'")'),
      "ok.go": handler('w.Write([]byte("ok"))'),
    });
    expect(rules(dir)).toEqual([]);
  });

  it("a function that never sees the request is not a source of findings", () => {
    const dir = project({
      "main.go": ['package main', '', 'func build(name string) string {', '\treturn "SELECT * FROM t WHERE n = \'" + name + "\'"', '}', 'func run() { db.Query(build("x")) }'],
    });
    expect(hits(dir, "sql-injection")).toEqual([]);
  });
});
