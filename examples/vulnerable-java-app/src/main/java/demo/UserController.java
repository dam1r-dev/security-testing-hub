// A deliberately vulnerable Spring MVC controller: a fixture for the scanner's tests. Do not deploy.
package demo;

import demo.service.UserService;
import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Paths;
import javax.servlet.http.HttpServletRequest;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class UserController {
    private final JdbcTemplate jdbc;
    private final UserService users;

    public UserController(JdbcTemplate jdbc, UserService users) {
        this.jdbc = jdbc;
        this.users = users;
    }

    // SQL injection: the name goes into the query text.
    @GetMapping("/search")
    public Object search(@RequestParam String name) {
        return jdbc.queryForList("SELECT id, email FROM users WHERE name = '" + name + "'");
    }

    // Safe: the value is passed as a parameter.
    @GetMapping("/search-safe")
    public Object searchSafe(@RequestParam String name) {
        return jdbc.queryForList("SELECT id, email FROM users WHERE name = ?", name);
    }

    // The query is built in another class (service/UserService.java).
    @GetMapping("/user")
    public Object user(@RequestParam String email) {
        return users.findByEmail(email);
    }

    // Safe: the id is parsed to a number first.
    @GetMapping("/item")
    public Object item(@RequestParam String id) {
        long n = Long.parseLong(id);
        return jdbc.queryForList("SELECT title FROM items WHERE id = " + n);
    }

    // Command injection.
    @GetMapping("/ping")
    public String ping(@RequestParam String host) throws IOException {
        Runtime.getRuntime().exec("ping -c 1 " + host);
        return "ok";
    }

    // Path traversal.
    @GetMapping("/download")
    public byte[] download(@RequestParam String file) throws IOException {
        return Files.readAllBytes(Paths.get("/var/data/" + file));
    }

    // SSRF.
    @GetMapping("/preview")
    public String preview(@RequestParam String url) throws IOException {
        return new String(new URL(url).openStream().readAllBytes());
    }

    // XSS: the name is returned as HTML.
    @GetMapping("/hello")
    public String hello(@RequestParam String name) {
        return "<h1>Hello " + name + "</h1>";
    }

    // Expression injection: the request is evaluated by SpEL.
    @PostMapping("/calc")
    public Object calc(@RequestBody String expression) {
        ExpressionParser parser = new SpelExpressionParser();
        return parser.parseExpression(expression).getValue();
    }

    // Open redirect, from a servlet-style handler.
    @GetMapping("/go")
    public String go(HttpServletRequest request) {
        return "redirect:" + request.getParameter("next");
    }
}
