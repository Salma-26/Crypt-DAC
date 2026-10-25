package com.cryptdac.web;

import com.cryptdac.util.*;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.*;
import java.io.IOException;
import java.net.URLEncoder;
import java.security.KeyPair;
import java.sql.*;

@WebServlet("/auth")
public class AuthServlet extends HttpServlet {
    private static String[] meta(String role) {
        if ("owner".equals(role)) return new String[]{"data_owners", "owner_id", "owner_name"};
        if ("user".equals(role)) return new String[]{"end_users", "user_id", "user_name"};
        return null;
    }

    private void back(HttpServletResponse rs, String page, String msg) throws IOException {
        rs.sendRedirect(page + "?msg=" + URLEncoder.encode(msg, "UTF-8"));
    }

    @Override
    protected void doPost(HttpServletRequest rq, HttpServletResponse rs) throws IOException {
        String action = rq.getParameter("action"), role = rq.getParameter("role");
        String name = rq.getParameter("name"), pw = rq.getParameter("password");
        try {
            if ("logout".equals(action)) {
                HttpSession s = rq.getSession(false);
                if (s != null) s.invalidate();
                back(rs, "index.jsp", "Signed out"); return;
            }
            if (name == null || pw == null || name.isBlank() || pw.length() < 6) {
                back(rs, "index.jsp", "Enter a name and a password of at least 6 characters"); return;
            }
            if ("login".equals(action) && "cloud".equals(role)) {
                if (name.equals(DB.prop("cloud.user")) && pw.equals(DB.prop("cloud.password"))) {
                    rq.changeSessionId();
                    rq.getSession().setAttribute("role", "cloud");
                    rs.sendRedirect("cloud.jsp"); return;
                }
                back(rs, "index.jsp", "Wrong cloud credentials"); return;
            }
            String[] m = meta(role);
            if (m == null) { back(rs, "index.jsp", "Unknown role"); return; }
            try (Connection c = DB.get()) {
                if ("register".equals(action)) {
                    String email = rq.getParameter("email");
                    KeyPair kp = CryptoUtil.genRsa();
                    byte[] keySalt = CryptoUtil.rand(16);
                    byte[] encPriv = CryptoUtil.aesEnc(CryptoUtil.pbkdf2(pw, keySalt), kp.getPrivate().getEncoded());
                    try (PreparedStatement p = c.prepareStatement("INSERT INTO " + m[0] + "(" + m[2] +
                            ",email,password_hash,key_salt,pub_key,enc_priv) VALUES(?,?,?,?,?,?)")) {
                        p.setString(1, name); p.setString(2, email == null ? "" : email);
                        p.setString(3, CryptoUtil.hashPassword(pw)); p.setString(4, CryptoUtil.b64(keySalt));
                        p.setString(5, CryptoUtil.b64(kp.getPublic().getEncoded())); p.setString(6, CryptoUtil.b64(encPriv));
                        p.executeUpdate();
                    }
                    back(rs, "index.jsp", "Registered. Wait for the cloud server to authorize your account."); return;
                }
                try (PreparedStatement p = c.prepareStatement("SELECT " + m[1] + ",password_hash,key_salt,enc_priv,status FROM " + m[0] + " WHERE " + m[2] + "=?")) {
                    p.setString(1, name);
                    try (ResultSet r = p.executeQuery()) {
                        if (!r.next() || !CryptoUtil.verifyPassword(pw, r.getString(2))) { back(rs, "index.jsp", "Wrong name or password"); return; }
                        if (!"authorized".equals(r.getString(5))) { back(rs, "index.jsp", "Account is waiting for cloud authorization"); return; }
                        byte[] priv = CryptoUtil.aesDec(CryptoUtil.pbkdf2(pw, CryptoUtil.unb64(r.getString(3))), CryptoUtil.unb64(r.getString(4)));
                        rq.changeSessionId();
                        HttpSession s = rq.getSession();
                        s.setAttribute("role", role); s.setAttribute("id", r.getInt(1));
                        s.setAttribute("name", name); s.setAttribute("priv", priv);
                        rs.sendRedirect(role + ".jsp");
                    }
                }
            }
        } catch (SQLIntegrityConstraintViolationException e) {
            back(rs, "index.jsp", "That name is already taken");
        } catch (Exception e) {
            back(rs, "index.jsp", "Error: " + e.getMessage());
        }
    }
}
