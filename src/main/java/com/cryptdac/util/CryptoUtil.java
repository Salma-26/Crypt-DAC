package com.cryptdac.util;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.*;
import java.util.Arrays;
import java.util.Base64;

/** All cryptography used by Crypt-DAC: AES-256-GCM layers, RSA-OAEP key wrapping, PBKDF2. */
public class CryptoUtil {
    private static final SecureRandom R = new SecureRandom();
    public static final int KEY = 32;

    public static byte[] rand(int n) { byte[] b = new byte[n]; R.nextBytes(b); return b; }
    public static String b64(byte[] b) { return Base64.getEncoder().encodeToString(b); }
    public static byte[] unb64(String s) { return Base64.getDecoder().decode(s); }

    /** AES-256-GCM. Output = 12-byte IV || ciphertext+tag. */
    public static byte[] aesEnc(byte[] key, byte[] data) throws GeneralSecurityException {
        byte[] iv = rand(12);
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, iv));
        byte[] ct = c.doFinal(data);
        byte[] out = new byte[12 + ct.length];
        System.arraycopy(iv, 0, out, 0, 12);
        System.arraycopy(ct, 0, out, 12, ct.length);
        return out;
    }

    public static byte[] aesDec(byte[] key, byte[] data) throws GeneralSecurityException {
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"),
                new GCMParameterSpec(128, Arrays.copyOfRange(data, 0, 12)));
        return c.doFinal(data, 12, data.length - 12);
    }

    public static byte[] pbkdf2(String pw, byte[] salt) throws GeneralSecurityException {
        SecretKeyFactory f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        return f.generateSecret(new PBEKeySpec(pw.toCharArray(), salt, 120000, 256)).getEncoded();
    }

    public static String hashPassword(String pw) throws GeneralSecurityException {
        byte[] salt = rand(16);
        return b64(salt) + ":" + b64(pbkdf2(pw, salt));
    }

    public static boolean verifyPassword(String pw, String stored) throws GeneralSecurityException {
        String[] p = stored.split(":");
        return MessageDigest.isEqual(pbkdf2(pw, unb64(p[0])), unb64(p[1]));
    }

    public static KeyPair genRsa() throws GeneralSecurityException {
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        g.initialize(2048);
        return g.generateKeyPair();
    }

    public static PublicKey pubFrom(String b64) throws GeneralSecurityException {
        return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(unb64(b64)));
    }

    public static PrivateKey privFrom(byte[] pkcs8) throws GeneralSecurityException {
        return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(pkcs8));
    }

    /** Hybrid wrap: RSA-OAEP(session key) : AES-GCM(session key, key list). */
    public static String wrap(byte[] keyList, PublicKey pk) throws GeneralSecurityException {
        byte[] s = rand(KEY);
        Cipher c = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        c.init(Cipher.ENCRYPT_MODE, pk);
        return b64(c.doFinal(s)) + ":" + b64(aesEnc(s, keyList));
    }

    public static byte[] unwrap(String wrapped, PrivateKey sk) throws GeneralSecurityException {
        String[] x = wrapped.split(":");
        Cipher c = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        c.init(Cipher.DECRYPT_MODE, sk);
        return aesDec(c.doFinal(unb64(x[0])), unb64(x[1]));
    }

    /** Key list layout: Kf || Kr1 || ... || Krn (32 bytes each). Outermost layer = Krn. */
    public static byte[] decryptLayers(byte[] ct, byte[] keyList, int layers) throws GeneralSecurityException {
        if (keyList.length < (layers + 1) * KEY)
            throw new GeneralSecurityException("Key list is stale: access has been revoked");
        byte[] d = ct;
        for (int i = layers; i >= 1; i--)
            d = aesDec(Arrays.copyOfRange(keyList, i * KEY, i * KEY + KEY), d);
        return aesDec(Arrays.copyOfRange(keyList, 0, KEY), d);
    }

    public static byte[] concat(byte[] a, byte[] b) {
        byte[] o = Arrays.copyOf(a, a.length + b.length);
        System.arraycopy(b, 0, o, a.length, b.length);
        return o;
    }
}
