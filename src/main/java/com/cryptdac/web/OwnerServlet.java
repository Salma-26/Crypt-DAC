package com.cryptdac.web;

import com.cryptdac.util.*;
import javax.servlet.annotation.MultipartConfig;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.*;
import java.io.IOException;
import java.net.URLEncoder;
import java.nio.file.Paths;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.sql.*;

@WebServlet("/owner")
@MultipartConfig(maxFileSize = 50L * 1024 * 1024)
public class OwnerServlet extends HttpServlet {
    @Override
    protected void doPost(HttpServletRequest rq, HttpServletResponse rs) throws IOException {
        HttpSession s = rq.getSession(false);
        if (s == null || !"owner".equals(s.getAttribute("role"))) { rs.sendRedirect("index.jsp"); return; }
        int oid = (Integer) s.getAttribute("id");
        String a = String.valueOf(rq.getParameter("action")), msg;
        long t0 = System.currentTimeMillis();
        try (Connection c = DB.get()) {
            PrivateKey priv = CryptoUtil.privFrom((byte[]) s.getAttribute("priv"));
            PublicKey pub = FileService.ownerPub(c, oid);
            int fid = rq.getParameter("file") == null ? 0 : Integer.parseInt(rq.getParameter("file"));
            switch (a) {
                case "upload": {
                    Part f = rq.getPart("file");
                    byte[] d = f.getInputStream().readAllBytes();
                    String n = Paths.get(f.getSubmittedFileName()).getFileName().toString();
                    int id = FileService.create(c, oid, n, d, pub);
                    FileService.log(c, oid, 0, id, "UPLOAD", n, System.currentTimeMillis() - t0, d.length);
                    msg = "Encrypted and uploaded " + n; break;
                }
                case "update": {
                    if (!FileService.owns(c, oid, fid)) throw new SecurityException("Not your file");
                    byte[] d = rq.getPart("newfile").getInputStream().readAllBytes();
                    FileService.write(c, fid, d, pub);
                    FileService.log(c, oid, 0, fid, "UPDATE", "write + de-onion", System.currentTimeMillis() - t0, d.length);
                    msg = "File rewritten, onion layers cleared"; break;
                }
                case "delete": {
                    if (!FileService.owns(c, oid, fid)) throw new SecurityException("Not your file");
                    try (PreparedStatement p = c.prepareStatement("DELETE FROM file_chunks WHERE file_id=?")) { p.setInt(1, fid); p.executeUpdate(); }
                    try (PreparedStatement p = c.prepareStatement("UPDATE access_policies SET active=0 WHERE file_id=?")) { p.setInt(1, fid); p.executeUpdate(); }
                    try (PreparedStatement p = c.prepareStatement("UPDATE files SET is_deleted=1 WHERE file_id=?")) { p.setInt(1, fid); p.executeUpdate(); }
                    FileService.log(c, oid, 0, fid, "DELETE", "file removed", System.currentTimeMillis() - t0, 0);
                    msg = "File deleted"; break;
                }
                case "verify": {
                    if (!FileService.owns(c, oid, fid)) throw new SecurityException("Not your file");
                    String stored = null;
                    try (PreparedStatement p = c.prepareStatement("SELECT checksum FROM files WHERE file_id=?")) {
                        p.setInt(1, fid);
                        try (ResultSet r = p.executeQuery()) { r.next(); stored = r.getString(1); }
                    }
                    boolean ok = stored != null && stored.equals(FileService.checksum(c, fid));
                    FileService.log(c, oid, 0, fid, "VERIFY", ok ? "intact" : "TAMPERED", System.currentTimeMillis() - t0, 0);
                    msg = ok ? "Integrity check passed" : "WARNING: ciphertext does not match its checksum"; break;
                }
                case "grant": {
                    if (!FileService.owns(c, oid, fid)) throw new SecurityException("Not your file");
                    int uid = Integer.parseInt(rq.getParameter("user"));
                    int hours = Integer.parseInt(rq.getParameter("hours"));
                    PublicKey upub;
                    try (PreparedStatement p = c.prepareStatement("SELECT pub_key FROM end_users WHERE user_id=? AND status='authorized'")) {
                        p.setInt(1, uid);
                        try (ResultSet r = p.executeQuery()) {
                            if (!r.next()) throw new IllegalArgumentException("User not authorized");
                            upub = CryptoUtil.pubFrom(r.getString(1));
                        }
                    }
                    String wrapped = CryptoUtil.wrap(FileService.keyList(c, fid, priv), upub);
                    try (PreparedStatement p = c.prepareStatement(
                            "INSERT INTO access_policies(file_id,allowed_user_id,privilege,expiration_time,wrapped_keys,active) VALUES(?,?,?,?,?,1) " +
                            "ON DUPLICATE KEY UPDATE privilege=VALUES(privilege),expiration_time=VALUES(expiration_time),wrapped_keys=VALUES(wrapped_keys),active=1")) {
                        p.setInt(1, fid); p.setInt(2, uid); p.setString(3, rq.getParameter("privilege"));
                        if (hours > 0) p.setTimestamp(4, new Timestamp(System.currentTimeMillis() + hours * 3600_000L));
                        else p.setNull(4, Types.TIMESTAMP);
                        p.setString(5, wrapped); p.executeUpdate();
                    }
                    try (PreparedStatement p = c.prepareStatement("UPDATE access_requests SET status='approved' WHERE file_id=? AND user_id=?")) {
                        p.setInt(1, fid); p.setInt(2, uid); p.executeUpdate();
                    }
                    FileService.log(c, oid, uid, fid, "GRANT", "policy set", System.currentTimeMillis() - t0, 0);
                    msg = "Access granted"; break;
                }
                case "revoke": {
                    int pid = Integer.parseInt(rq.getParameter("policy"));
                    FileService.revokePolicy(c, oid, pid, priv, pub);
                    FileService.log(c, oid, 0, 0, "REVOKE", "policy " + pid, System.currentTimeMillis() - t0, 0);
                    msg = "Access revoked immediately (new onion layer added)"; break;
                }
                default: msg = "Unknown action";
            }
        } catch (Exception e) { msg = "Error: " + e.getMessage(); }
        rs.sendRedirect("owner.jsp?msg=" + URLEncoder.encode(msg, "UTF-8"));
    }
}
