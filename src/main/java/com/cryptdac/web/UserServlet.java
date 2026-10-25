package com.cryptdac.web;

import com.cryptdac.util.*;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.*;
import java.io.IOException;
import java.net.URLEncoder;
import java.security.PrivateKey;
import java.sql.*;

@WebServlet("/user")
public class UserServlet extends HttpServlet {
    private HttpSession guard(HttpServletRequest rq, HttpServletResponse rs) throws IOException {
        HttpSession s = rq.getSession(false);
        if (s == null || !"user".equals(s.getAttribute("role"))) { rs.sendRedirect("index.jsp"); return null; }
        return s;
    }

    @Override
    protected void doPost(HttpServletRequest rq, HttpServletResponse rs) throws IOException {
        HttpSession s = guard(rq, rs); if (s == null) return;
        int uid = (Integer) s.getAttribute("id"), fid = Integer.parseInt(rq.getParameter("file")); String msg;
        try (Connection c = DB.get()) {
            try (PreparedStatement p = c.prepareStatement(
                    "INSERT INTO access_requests(user_id,file_id) SELECT ?,? FROM DUAL WHERE EXISTS(SELECT 1 FROM files WHERE file_id=? AND is_deleted=0) " +
                    "AND NOT EXISTS(SELECT 1 FROM access_requests WHERE user_id=? AND file_id=? AND status='pending')")) {
                p.setInt(1, uid); p.setInt(2, fid); p.setInt(3, fid); p.setInt(4, uid); p.setInt(5, fid);
                msg = p.executeUpdate() > 0 ? "Request sent to the data owner" : "Request already pending";
            }
        } catch (Exception e) { msg = "Error: " + e.getMessage(); }
        rs.sendRedirect("user.jsp?msg=" + URLEncoder.encode(msg, "UTF-8"));
    }

    /** Download: unwrap key list with the user's private key, strip onion layers, decrypt. */
    @Override
    protected void doGet(HttpServletRequest rq, HttpServletResponse rs) throws IOException {
        HttpSession s = guard(rq, rs); if (s == null) return;
        int uid = (Integer) s.getAttribute("id");
        long t0 = System.currentTimeMillis();
        try (Connection c = DB.get()) {
            int fid = Integer.parseInt(rq.getParameter("file"));
            String wrapped, name; int layers, owner;
            try (PreparedStatement p = c.prepareStatement(
                    "SELECT p.wrapped_keys,f.layer_count,f.file_name,f.owner_id FROM access_policies p JOIN files f ON p.file_id=f.file_id " +
                    "WHERE p.file_id=? AND p.allowed_user_id=? AND p.active=1 AND f.is_deleted=0 AND (p.expiration_time IS NULL OR p.expiration_time>NOW())")) {
                p.setInt(1, fid); p.setInt(2, uid);
                try (ResultSet r = p.executeQuery()) {
                    if (!r.next()) { rs.sendRedirect("user.jsp?msg=" + URLEncoder.encode("Access denied: no active permission", "UTF-8")); return; }
                    wrapped = r.getString(1); layers = r.getInt(2); name = r.getString(3); owner = r.getInt(4);
                }
            }
            PrivateKey priv = CryptoUtil.privFrom((byte[]) s.getAttribute("priv"));
            byte[] data = FileService.readPlain(c, fid, CryptoUtil.unwrap(wrapped, priv), layers);
            FileService.log(c, owner, uid, fid, "DOWNLOAD", name, System.currentTimeMillis() - t0, data.length);
            rs.setContentType("application/octet-stream");
            rs.setHeader("Content-Disposition", "attachment; filename=\"" + name.replaceAll("[\"\\r\\n]", "_") + "\"");
            rs.setContentLength(data.length);
            rs.getOutputStream().write(data);
        } catch (Exception e) {
            rs.sendRedirect("user.jsp?msg=" + URLEncoder.encode("Access denied: " + e.getMessage(), "UTF-8"));
        }
    }
}
