package com.cryptdac.web;

import javax.servlet.annotation.WebServlet;
import javax.servlet.http.*;
import com.cryptdac.util.DB;
import java.io.IOException;
import java.net.URLEncoder;
import java.sql.*;

@WebServlet("/cloud")
public class CloudServlet extends HttpServlet {
    @Override
    protected void doPost(HttpServletRequest rq, HttpServletResponse rs) throws IOException {
        HttpSession s = rq.getSession(false);
        if (s == null || !"cloud".equals(s.getAttribute("role"))) { rs.sendRedirect("index.jsp"); return; }
        String role = rq.getParameter("role"), msg;
        String table = "owner".equals(role) ? "data_owners" : "user".equals(role) ? "end_users" : null;
        String idcol = "owner".equals(role) ? "owner_id" : "user_id";
        try (Connection c = DB.get()) {
            if (table == null) throw new IllegalArgumentException("Unknown role");
            try (PreparedStatement p = c.prepareStatement("UPDATE " + table + " SET status='authorized' WHERE " + idcol + "=?")) {
                p.setInt(1, Integer.parseInt(rq.getParameter("id"))); p.executeUpdate();
            }
            msg = "Account authorized";
        } catch (Exception e) { msg = "Error: " + e.getMessage(); }
        rs.sendRedirect("cloud.jsp?msg=" + URLEncoder.encode(msg, "UTF-8"));
    }
}
