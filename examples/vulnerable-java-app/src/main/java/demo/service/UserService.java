// The service layer of the Java example: the dangerous query lives here, one call away from the controller.
package demo.service;

import java.util.List;
import java.util.Map;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

@Service
public class UserService {
    private final JdbcTemplate jdbc;

    public UserService(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    // Builds the query from text: a controller that passes the request's value in is vulnerable.
    public List<Map<String, Object>> findByEmail(String email) {
        return jdbc.queryForList("SELECT id, email FROM users WHERE email = '" + email + "'");
    }
}
