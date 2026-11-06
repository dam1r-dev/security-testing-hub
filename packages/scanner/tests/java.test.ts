import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { scanPath } from "../src";

jest.setTimeout(60_000);

function project(files: Record<string, string[]>): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "hub-java-"));
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

/** Body lines wrapped into a servlet (`request`, `response`) in a file of its own. */
function servlet(...body: string[]): string[] {
  return [
    'import javax.servlet.http.*;', 'import java.sql.*;', 'import java.io.*;', '',
    'public class S extends HttpServlet {',
    '  protected void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {',
    ...body.map((l) => `    ${l}`),
    '  }', '}',
  ];
}
// the first body line is line 7

/** Body lines wrapped into a Spring handler with `@RequestParam String name`. */
function spring(...body: string[]): string[] {
  return [
    'import org.springframework.web.bind.annotation.*;', '',
    '@RestController', 'public class C {',
    '  @GetMapping("/x")',
    '  public Object x(@RequestParam String name, @RequestParam Long id) throws Exception {',
    ...body.map((l) => `    ${l}`),
    '  }', '}',
  ];
}
// the first body line is line 7

describe("Java: SQL injection", () => {
  it("a query built from the request, in a servlet and in a Spring handler", () => {
    const dir = project({
      "S.java": servlet('String id = request.getParameter("id");', 'Statement st = conn.createStatement();', 'st.executeQuery("SELECT * FROM t WHERE id = " + id);', 'conn.prepareStatement(String.format("SELECT %s", id));'),
      "C.java": spring('return jdbc.queryForList("SELECT * FROM users WHERE name = \'" + name + "\'");'),
    });
    expect(hits(dir, "sql-injection").map((h) => `${h.file}:${h.line}`).sort()).toEqual(["C.java:7", "S.java:10", "S.java:9"]);
  });

  it("values passed separately, a number parsed first and a numeric parameter are fine", () => {
    const dir = project({
      "C.java": spring(
        'jdbc.queryForList("SELECT * FROM users WHERE name = ?", name);',
        'long n = Long.parseLong(name);',
        'jdbc.queryForList("SELECT * FROM t WHERE id = " + n);',
        'jdbc.queryForList("SELECT * FROM t WHERE id = " + id);',
      ),
    });
    expect(hits(dir, "sql-injection")).toEqual([]);
  });

  it("JPA native queries and StringBuilder", () => {
    const dir = project({
      "C.java": spring('em.createNativeQuery("select * from t where n = \'" + name + "\'").getResultList();', 'StringBuilder sb = new StringBuilder("SELECT * FROM t WHERE ");', 'sb.append("a = ").append(name);', 'st.execute(sb.toString());'),
    });
    expect(hits(dir, "sql-injection").map((h) => h.line)).toEqual([7, 10]);
  });
});

describe("Java: commands, files, requests, redirects, HTML", () => {
  it("Runtime.exec with the request, ProcessBuilder through a shell", () => {
    const dir = project({
      "S.java": servlet('String host = request.getParameter("h");', 'Runtime.getRuntime().exec("ping " + host);', 'new ProcessBuilder("sh", "-c", "ping " + host).start();', 'new ProcessBuilder("ping", "-c", "1", host).start();', 'Runtime rt = Runtime.getRuntime(); rt.exec(new String[] {"ls"});'),
    });
    expect(hits(dir, "command-injection").map((h) => h.line)).toEqual([8, 9]);
  });

  it("file paths: opened as sent, safe with a base name", () => {
    const dir = project({
      "S.java": servlet('String f = request.getParameter("file");', 'new FileInputStream(new File("/data/" + f));', 'java.nio.file.Files.readAllBytes(java.nio.file.Paths.get(f));'),
      "Safe.java": servlet('String f = org.apache.commons.io.FilenameUtils.getName(request.getParameter("file"));', 'new FileInputStream(new File("/data/" + f));'),
    });
    expect(hits(dir, "path-traversal").map((h) => `${h.file}:${h.line}`)).toEqual(["S.java:8", "S.java:9"]);
  });

  it("SSRF: the URL from the request, not a fixed host or a path from the request line", () => {
    const dir = project({
      "S.java": servlet(
        'String u = request.getParameter("url");',
        'new URL(u).openStream();',
        'new URL("https://api.example.com/users/" + request.getParameter("id")).openStream();',
        'new URL("http://0.0.0.0" + request.getRequestURI()).openStream();',
      ),
    });
    expect(hits(dir, "ssrf").map((h) => h.line)).toEqual([8]);
  });

  it("redirects: judged by who controls the start of the address", () => {
    const dir = project({
      "S.java": servlet(
        'response.sendRedirect(request.getParameter("next"));',
        'response.sendRedirect(baseUrl + "/x?tab=" + request.getParameter("tab"));',
        'response.sendRedirect("/items/" + request.getParameter("id"));',
      ),
      "C.java": spring('return "redirect:" + name;'),
    });
    expect(hits(dir, "open-redirect").map((h) => `${h.file}:${h.line}`).sort()).toEqual(["C.java:7", "S.java:7"]);
  });

  it("HTML written to the response, and a controller that returns HTML text", () => {
    const dir = project({
      "S.java": servlet('PrintWriter out = response.getWriter();', 'out.println("<h1>" + request.getParameter("n") + "</h1>");', 'response.getWriter().print(request.getParameter("m"));'),
      "C.java": spring('return "<h1>Hello " + name + "</h1>";'),
      "Json.java": spring('return "{\\"name\\": \\"" + name + "\\"}";'),
    });
    expect(hits(dir, "xss").map((h) => `${h.file}:${h.line}`).sort()).toEqual(["C.java:7", "S.java:8", "S.java:9"]);
  });
});

describe("Java: frameworks and data flow", () => {
  it("Spring binds a plain handler parameter, a DTO and JAX-RS annotations", () => {
    const dir = project({
      "A.java": [
        'import org.springframework.web.bind.annotation.*;', 'public class A {',
        '  @PostMapping("/a") public void a(String plain, Dto dto) { jdbc.execute("DELETE FROM t WHERE a = \'" + plain + "\' AND b = \'" + dto.getName() + "\'"); }',
        '}',
      ],
      "B.java": [
        'import javax.ws.rs.*;', 'public class B {',
        '  @GET @Path("/b") public void b(@QueryParam("q") String q) { st.executeQuery("SELECT * FROM t WHERE q = \'" + q + "\'"); }',
        '}',
      ],
    });
    expect(hits(dir, "sql-injection").map((h) => `${h.file}:${h.line}`).sort()).toEqual(["A.java:3", "B.java:3"]);
  });

  it("a clean assignment in another branch does not undo the taint", () => {
    const dir = project({
      "S.java": servlet('String bar;', 'switch (request.getParameter("k").length()) { case 1: bar = request.getParameter("p"); break; default: bar = "safe"; }', 'st.executeQuery("SELECT * FROM t WHERE x = \'" + bar + "\'");'),
    });
    expect(hits(dir, "sql-injection").map((h) => h.line)).toEqual([9]);
  });

  it("a value that comes back out of a helper declared in the same file", () => {
    const dir = project({
      "S.java": [
        'import javax.servlet.http.*;', 'public class S extends HttpServlet {',
        '  protected void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {',
        '    String bar = new Inner().pick(request, request.getParameter("p"));',
        '    st.executeQuery("SELECT * FROM t WHERE x = \'" + bar + "\'");',
        '    String clean = new Inner().fixed(request, request.getParameter("p"));',
        '    st.executeQuery("SELECT * FROM t WHERE x = \'" + clean + "\'");',
        '  }',
        '  private class Inner {',
        '    String pick(HttpServletRequest r, String p) { return p.trim(); }',
        '    String fixed(HttpServletRequest r, String p) { return "constant"; }',
        '  }',
        '}',
      ],
    });
    expect(hits(dir, "sql-injection").map((h) => h.line)).toEqual([5]);
  });

  it("the query is built in a service class of another file", () => {
    const dir = project({
      "C.java": spring('return users.findByEmail(name);'),
      "UserService.java": [
        'public class UserService {',
        '  public Object findByEmail(String email) { return jdbc.queryForList("SELECT * FROM users WHERE email = \'" + email + "\'"); }',
        '}',
      ],
    });
    expect(hits(dir, "sql-injection").map((h) => `${h.file}:${h.line}`)).toEqual(["C.java:7"]);
  });

  it("a wrapper around the request hands out the same values", () => {
    const dir = project({
      "S.java": servlet('RequestWrapper scr = new RequestWrapper(request);', 'String p = scr.getTheParameter("x");', 'st.executeQuery("SELECT * FROM t WHERE x = \'" + p + "\'");'),
    });
    expect(hits(dir, "sql-injection").map((h) => h.line)).toEqual([9]);
  });

  it("other templates, and a Scanner over a stream, are not outgoing requests or files", () => {
    const dir = project({
      "C.java": spring('redisTemplate.delete(name);', 'new java.util.Scanner(request.getInputStream());', 'restTemplate.getForObject(name, String.class);'),
    });
    expect(hits(dir).map((h) => `${h.rule}:${h.line}`)).toEqual(["ssrf:9"]);
  });
});

describe("Java: deserialization and code", () => {
  it("ObjectInputStream over the request, SnakeYAML, SpEL", () => {
    const dir = project({
      "S.java": servlet('new ObjectInputStream(request.getInputStream()).readObject();', 'new Yaml().load(request.getParameter("y"));', 'new SpelExpressionParser().parseExpression(request.getParameter("e"));'),
    });
    expect(hits(dir).map((h) => `${h.rule}:${h.line}`)).toEqual(["insecure-deserialization:7", "insecure-deserialization:8", "code-injection:9"]);
  });
});

describe("Java: patterns without data flow", () => {
  it("weak hashes and ciphers, bcrypt cost, java.util.Random for a token", () => {
    const dir = project({
      "K.java": [
        'import java.security.*;', 'import javax.crypto.*;', 'import java.util.Random;', 'public class K {',
        '  byte[] hashPassword(String password) throws Exception { return MessageDigest.getInstance("MD5").digest(password.getBytes()); }',
        '  byte[] checksum(byte[] data) throws Exception { return MessageDigest.getInstance("MD5").digest(data); }',
        '  Cipher c() throws Exception { return Cipher.getInstance("AES"); }',
        '  Cipher g() throws Exception { return Cipher.getInstance("AES/GCM/NoPadding"); }',
        '  String resetToken() { Random r = new Random(); String token = Long.toString(r.nextLong()); return token; }',
        '  Object enc() { return new BCryptPasswordEncoder(4); }',
        '}',
      ],
    });
    expect(hits(dir, "weak-crypto").map((h) => h.line)).toEqual([5, 7, 10]);
  });

  it("Spring Security: CSRF off, every route open, every origin with cookies", () => {
    const dir = project({
      "Sec.java": [
        'public class Sec {',
        '  void a(HttpSecurity http) throws Exception { http.csrf().disable().authorizeRequests().anyRequest().permitAll(); }',
        '  void b(CorsRegistry r) { r.addMapping("/**").allowedOrigins("*").allowCredentials(true); }',
        '}',
      ],
    });
    expect(hits(dir).map((h) => `${h.rule}:${h.line}`).sort()).toEqual(["broken-access-control:2", "csrf:2", "insecure-cors:3"]);
  });

  it("a stateless API without CSRF is reported with low confidence", () => {
    const dir = project({
      "Sec.java": ['public class Sec {', '  void a(HttpSecurity http) throws Exception { http.csrf().disable().sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS); }', '}'],
    });
    expect(hits(dir, "csrf").map((h) => h.confidence)).toEqual(["low"]);
  });

  it("certificate and host-name checks, cookies, JWT, XML parsers, signing keys", () => {
    const dir = project({
      "T.java": [
        'import javax.servlet.http.*;', 'public class T {',
        '  Object v() { return NoopHostnameVerifier.INSTANCE; }',
        '  void tm() { }',
        '  public void checkServerTrusted(java.security.cert.X509Certificate[] c, String a) { }',
        '  void cookie(HttpServletResponse r) { Cookie ok = new Cookie("sessionId", "x"); ok.setHttpOnly(true); Cookie bad = new Cookie("sessionId", "y"); r.addCookie(ok); r.addCookie(bad); r.addCookie(new Cookie("sessionId", "")); }',
        '  void jwt() { Jwts.parser().parseClaimsJwt("t"); }',
        '  void xml() throws Exception { DocumentBuilderFactory.newInstance(); }',
        '  Object key() { return Algorithm.HMAC256("not-a-real-signing-key-1"); }',
        '}',
      ],
    });
    expect(hits(dir).map((h) => `${h.rule}:${h.line}`).sort()).toEqual(["hardcoded-secret:9", "insecure-cookie:6", "insecure-jwt:7", "tls-verification:3", "tls-verification:5", "xxe:8"]);
  });

  it("a secret written in a field, not an environment variable's name or a property reference", () => {
    const dir = project({
      "Cfg.java": [
        'public class Cfg {',
        '  private static final String JWT_SECRET = "hunter2-hunter2-hunter2";',
        '  private static final String ENV_NAME = "APP_JWT_SECRET";',
        '  @Value("${app.secret}") private String fromProperties;',
        '  // example: redis://user:pass@host:6379',
        '}',
      ],
    });
    expect(hits(dir, "hardcoded-secret").map((h) => h.line)).toEqual([2]);
  });
});

describe("Java: examples/vulnerable-java-app", () => {
  const dir = path.join(__dirname, "..", "..", "..", "examples", "vulnerable-java-app");
  const found = hits(dir);

  it("finds each planted flaw, once", () => {
    const counts: Record<string, number> = {};
    for (const h of found) counts[h.rule] = (counts[h.rule] ?? 0) + 1;
    expect(counts).toEqual({
      "sql-injection": 3, "command-injection": 1, "path-traversal": 1, ssrf: 1, xss: 2, "code-injection": 1, "open-redirect": 2, "insecure-deserialization": 1,
      "insecure-cookie": 1, csrf: 1, "broken-access-control": 1, "insecure-cors": 1, "hardcoded-secret": 1, "weak-crypto": 2, "tls-verification": 1, xxe: 1,
    });
  });

  it("follows the value into the service class, and leaves the safe handlers alone", () => {
    const controller = found.filter((h) => h.file === "UserController.java").map((h) => h.line);
    expect(controller).toContain(47); // users.findByEmail(email)
    expect(controller).not.toContain(42); // searchSafe: the value is a parameter
    expect(controller.filter((l) => l >= 49 && l <= 56)).toEqual([]); // item: parsed to a number first
  });
});

describe("Java: what is left out", () => {
  it("tests and build output are not scanned", () => {
    const dir = project({
      "src/test/java/ATest.java": servlet('st.executeQuery("SELECT " + request.getParameter("a"));'),
      "target/generated/B.java": servlet('st.executeQuery("SELECT " + request.getParameter("a"));'),
      "src/main/java/UserTest.java": servlet('st.executeQuery("SELECT " + request.getParameter("a"));'),
      "src/main/java/Ok.java": servlet('response.setStatus(200);'),
    });
    expect(hits(dir)).toEqual([]);
  });
});
