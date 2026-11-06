// Deliberately weak Spring Security and crypto settings: a fixture for the scanner's tests. Do not deploy.
package demo.config;

import java.security.MessageDigest;
import java.util.Random;
import javax.crypto.Cipher;
import javax.net.ssl.HostnameVerifier;
import javax.xml.parsers.DocumentBuilderFactory;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import com.auth0.jwt.algorithms.Algorithm;

@Configuration
public class SecurityConfig {
    // CSRF protection off and every route open.
    @Bean
    SecurityFilterChain chain(HttpSecurity http) throws Exception {
        http.csrf().disable().authorizeRequests().anyRequest().permitAll();
        return http.build();
    }

    // Every origin, with cookies.
    void cors(CorsRegistry registry) {
        registry.addMapping("/**").allowedOrigins("*").allowCredentials(true);
    }

    // A signing key written in the code.
    Algorithm algorithm() {
        return Algorithm.HMAC256("changeit-signing-key-2024");
    }

    // A weak password hash.
    byte[] hashPassword(String password) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        return md.digest(password.getBytes());
    }

    // A weak cipher.
    Cipher cipher() throws Exception {
        return Cipher.getInstance("DES");
    }

    // A predictable token.
    String resetToken() {
        Random random = new Random();
        return Long.toString(random.nextLong());
    }

    // Any host name accepted.
    HostnameVerifier verifier() {
        return NoopHostnameVerifier.INSTANCE;
    }

    // An XML parser that resolves external entities.
    DocumentBuilderFactory xml() {
        return DocumentBuilderFactory.newInstance();
    }
}
