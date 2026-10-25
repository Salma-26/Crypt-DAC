package com.cryptdac.util;

import java.io.ByteArrayOutputStream;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.sql.*;
import java.util.*;

/**
 * File operations. Methods labelled "cloud-side" only ever touch ciphertext and a revocation key,
 * never the file key Kf, matching the honest-but-curious model.
 */
public class FileService {
    public static final int CHUNK = 64 * 1024;
    public static final int MAX_LAYERS = 5; // tolerable onion bound; reset by the next write (delayed de-onion)

    public static PublicKey pub(Connection c, String table, String idcol, int id) throws Exception {
        try (PreparedStatement p = c.prepareStatement("SELECT pub_key FROM " + table + " WHERE " + idcol + "=?")) {
            p.setInt(1, id);
            try (ResultSet r = p.executeQuery()) { r.next(); return CryptoUtil.pubFrom(r.getString(1)); }
        }
    }
    public static PublicKey ownerPub(Connection c, int id) throws Exception { return pub(c, "data_owners", "owner_id", id); }

    public static void log(Connection c, int owner, int user, int file, String type, String msg, long ms, long bytes) throws SQLException {
        try (PreparedStatement p = c.prepareStatement(
                "INSERT INTO audit_logs(owner_id,user_id,file_id,action_type,action_message,elapsed_ms,bytes_processed) VALUES(?,?,?,?,?,?,?)")) {
            p.setInt(1, owner); p.setInt(2, user); p.setInt(3, file); p.setString(4, type);
            p.setString(5, msg); p.setLong(6, ms); p.setLong(7, bytes);
            p.executeUpdate();
        }
    }

    public static boolean owns(Connection c, int owner, int fid) throws SQLException {
        try (PreparedStatement p = c.prepareStatement("SELECT 1 FROM files WHERE file_id=? AND owner_id=? AND is_deleted=0")) {
            p.setInt(1, fid); p.setInt(2, owner);
            try (ResultSet r = p.executeQuery()) { return r.next(); }
        }
    }

    public static int create(Connection c, int owner, String name, byte[] data, PublicKey ownerPub) throws Exception {
        int fid;
        try (PreparedStatement p = c.prepareStatement("INSERT INTO files(owner_id,file_name,encrypted_key) VALUES(?,?,'')", Statement.RETURN_GENERATED_KEYS)) {
            p.setInt(1, owner); p.setString(2, name); p.executeUpdate();
            try (ResultSet r = p.getGeneratedKeys()) { r.next(); fid = r.getInt(1); }
        }
        write(c, fid, data, ownerPub);
        return fid;
    }

    /** Upload / update. Fresh Kf, layers reset to 0 (this is the delayed de-onion step), policies re-wrapped. */
    public static void write(Connection c, int fid, byte[] data, PublicKey ownerPub) throws Exception {
        byte[] kf = CryptoUtil.rand(CryptoUtil.KEY);
        try (PreparedStatement p = c.prepareStatement("DELETE FROM file_chunks WHERE file_id=?")) { p.setInt(1, fid); p.executeUpdate(); }
        try (PreparedStatement p = c.prepareStatement("INSERT INTO file_chunks(file_id,chunk_index,encrypted_chunk) VALUES(?,?,?)")) {
            int idx = 0;
            for (int off = 0; off < Math.max(data.length, 1); off += CHUNK) {
                byte[] ch = Arrays.copyOfRange(data, off, Math.min(data.length, off + CHUNK));
                p.setInt(1, fid); p.setInt(2, idx++); p.setBytes(3, CryptoUtil.aesEnc(kf, ch));
                p.executeUpdate();
            }
        }
        setKeys(c, fid, kf, 0, ownerPub);
        rewrapAll(c, fid, kf);
    }

    private static void setKeys(Connection c, int fid, byte[] list, int layers, PublicKey ownerPub) throws Exception {
        try (PreparedStatement p = c.prepareStatement("UPDATE files SET encrypted_key=?, layer_count=?, checksum=? WHERE file_id=?")) {
            p.setString(1, CryptoUtil.wrap(list, ownerPub)); p.setInt(2, layers);
            p.setString(3, checksum(c, fid)); p.setInt(4, fid); p.executeUpdate();
        }
    }

    public static String checksum(Connection c, int fid) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        try (PreparedStatement p = c.prepareStatement("SELECT encrypted_chunk FROM file_chunks WHERE file_id=? ORDER BY chunk_index")) {
            p.setInt(1, fid);
            try (ResultSet r = p.executeQuery()) { while (r.next()) md.update(r.getBytes(1)); }
        }
        return CryptoUtil.b64(md.digest());
    }

    public static byte[] keyList(Connection c, int fid, PrivateKey ownerPriv) throws Exception {
        try (PreparedStatement p = c.prepareStatement("SELECT encrypted_key FROM files WHERE file_id=?")) {
            p.setInt(1, fid);
            try (ResultSet r = p.executeQuery()) { r.next(); return CryptoUtil.unwrap(r.getString(1), ownerPriv); }
        }
    }

    /** Re-wrap the current key list for every active policy (done by the owner). */
    public static void rewrapAll(Connection c, int fid, byte[] list) throws Exception {
        Map<Integer, String> keys = new LinkedHashMap<>();
        try (PreparedStatement p = c.prepareStatement(
                "SELECT p.policy_id,u.pub_key FROM access_policies p JOIN end_users u ON p.allowed_user_id=u.user_id WHERE p.file_id=? AND p.active=1")) {
            p.setInt(1, fid);
            try (ResultSet r = p.executeQuery()) { while (r.next()) keys.put(r.getInt(1), r.getString(2)); }
        }
        try (PreparedStatement p = c.prepareStatement("UPDATE access_policies SET wrapped_keys=? WHERE policy_id=?")) {
            for (Map.Entry<Integer, String> e : keys.entrySet()) {
                p.setString(1, CryptoUtil.wrap(list, CryptoUtil.pubFrom(e.getValue())));
                p.setInt(2, e.getKey()); p.executeUpdate();
            }
        }
    }

    /** CLOUD-SIDE: wrap every chunk in one more AES layer using revocation key kr. */
    public static void addLayer(Connection c, int fid, byte[] kr) throws Exception {
        Map<Integer, byte[]> chunks = new LinkedHashMap<>();
        try (PreparedStatement p = c.prepareStatement("SELECT chunk_id,encrypted_chunk FROM file_chunks WHERE file_id=?")) {
            p.setInt(1, fid);
            try (ResultSet r = p.executeQuery()) { while (r.next()) chunks.put(r.getInt(1), r.getBytes(2)); }
        }
        try (PreparedStatement p = c.prepareStatement("UPDATE file_chunks SET encrypted_chunk=? WHERE chunk_id=?")) {
            for (Map.Entry<Integer, byte[]> e : chunks.entrySet()) {
                p.setBytes(1, CryptoUtil.aesEnc(kr, e.getValue())); p.setInt(2, e.getKey()); p.executeUpdate();
            }
        }
    }

    /** Revoke: deactivate policy, cloud adds a layer, owner appends Kr and re-wraps for remaining users. */
    public static void revokePolicy(Connection c, int owner, int policyId, PrivateKey priv, PublicKey pub) throws Exception {
        int fid = -1;
        try (PreparedStatement p = c.prepareStatement(
                "SELECT p.file_id FROM access_policies p JOIN files f ON p.file_id=f.file_id WHERE p.policy_id=? AND f.owner_id=? AND p.active=1")) {
            p.setInt(1, policyId); p.setInt(2, owner);
            try (ResultSet r = p.executeQuery()) { if (r.next()) fid = r.getInt(1); }
        }
        if (fid < 0) throw new IllegalArgumentException("Policy not found");
        try (PreparedStatement p = c.prepareStatement("UPDATE access_policies SET active=0 WHERE policy_id=?")) { p.setInt(1, policyId); p.executeUpdate(); }
        byte[] list = keyList(c, fid, priv);
        byte[] kr = CryptoUtil.rand(CryptoUtil.KEY);
        addLayer(c, fid, kr);
        byte[] newList = CryptoUtil.concat(list, kr);
        int layers = newList.length / CryptoUtil.KEY - 1;
        setKeys(c, fid, newList, layers, pub);
        rewrapAll(c, fid, newList);
    }

    public static int sweepExpired(Connection c, int owner, PrivateKey priv, PublicKey pub) throws Exception {
        List<Integer> ids = new ArrayList<>();
        try (PreparedStatement p = c.prepareStatement(
                "SELECT p.policy_id FROM access_policies p JOIN files f ON p.file_id=f.file_id " +
                "WHERE f.owner_id=? AND p.active=1 AND p.expiration_time IS NOT NULL AND p.expiration_time<NOW()")) {
            p.setInt(1, owner);
            try (ResultSet r = p.executeQuery()) { while (r.next()) ids.add(r.getInt(1)); }
        }
        for (int id : ids) revokePolicy(c, owner, id, priv, pub);
        return ids.size();
    }

    public static byte[] readPlain(Connection c, int fid, byte[] list, int layers) throws Exception {
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        try (PreparedStatement p = c.prepareStatement("SELECT encrypted_chunk FROM file_chunks WHERE file_id=? ORDER BY chunk_index")) {
            p.setInt(1, fid);
            try (ResultSet r = p.executeQuery()) { while (r.next()) o.write(CryptoUtil.decryptLayers(r.getBytes(1), list, layers)); }
        }
        return o.toByteArray();
    }
}
