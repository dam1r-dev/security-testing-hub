// A deliberately vulnerable servlet: a fixture for the scanner's tests. Do not deploy.
package demo;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.PrintWriter;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class LegacyServlet extends HttpServlet {
    private Connection conn;

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String id = req.getParameter("id");
        String name = req.getParameter("name");
        try {
            Statement st = conn.createStatement();
            ResultSet rs = st.executeQuery("SELECT * FROM users WHERE id = " + id);
            rs.close();
        } catch (Exception e) {
            resp.sendError(500);
        }
        // XSS: the name is written into the page.
        PrintWriter out = resp.getWriter();
        out.println("<h1>Welcome " + name + "</h1>");
        // Open redirect.
        resp.sendRedirect(req.getParameter("next"));
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException, ClassNotFoundException {
        // Insecure deserialization: the request body is read as Java objects.
        ObjectInputStream in = new ObjectInputStream(req.getInputStream());
        Object payload = in.readObject();
        // A login cookie that scripts can read.
        Cookie session = new Cookie("sessionId", String.valueOf(payload.hashCode()));
        resp.addCookie(session);
    }
}
