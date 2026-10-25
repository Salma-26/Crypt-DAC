package com.cryptdac.util;

import java.security.KeyPair;
import java.util.Arrays;

/** Database-free walkthrough of the Crypt-DAC lifecycle. Run: java -cp target/classes com.cryptdac.util.Demo */
public class Demo {
    public static void main(String[] a) throws Exception {
        KeyPair owner = CryptoUtil.genRsa(), alice = CryptoUtil.genRsa(), bob = CryptoUtil.genRsa();
        byte[] plain = "Quarterly report: confidential".getBytes();

        byte[] kf = CryptoUtil.rand(32);
        byte[] cloudCopy = CryptoUtil.aesEnc(kf, plain);
        byte[] list = kf; int layers = 0;
        String forAlice = CryptoUtil.wrap(list, alice.getPublic());
        String forBob = CryptoUtil.wrap(list, bob.getPublic());
        System.out.println("1. Owner uploads file, grants Alice and Bob (key list size: " + list.length + " bytes)");
        System.out.println("   Alice reads: " + new String(CryptoUtil.decryptLayers(cloudCopy, CryptoUtil.unwrap(forAlice, alice.getPrivate()), layers)));

        byte[] kr = CryptoUtil.rand(32);
        cloudCopy = CryptoUtil.aesEnc(kr, cloudCopy);           // cloud adds onion layer
        list = CryptoUtil.concat(list, kr); layers++;
        forBob = CryptoUtil.wrap(list, bob.getPublic());        // owner re-wraps for remaining user
        System.out.println("2. Owner revokes Alice: cloud adds layer " + layers + ", key list now " + list.length + " bytes");

        System.out.println("   Bob reads:   " + new String(CryptoUtil.decryptLayers(cloudCopy, CryptoUtil.unwrap(forBob, bob.getPrivate()), layers)));
        try {
            CryptoUtil.decryptLayers(cloudCopy, CryptoUtil.unwrap(forAlice, alice.getPrivate()), layers);
            System.out.println("   Alice reads: SECURITY FAILURE");
        } catch (Exception e) {
            System.out.println("   Alice reads: DENIED (" + e.getMessage() + ")");
        }

        byte[] kf2 = CryptoUtil.rand(32);                       // next write: delayed de-onion
        cloudCopy = CryptoUtil.aesEnc(kf2, plain); list = kf2; layers = 0;
        System.out.println("3. Next write resets onion: layers=" + layers + ", key list " + list.length + " bytes");
        System.out.println("   Round-trip OK: " + Arrays.equals(plain, CryptoUtil.decryptLayers(cloudCopy, list, layers)));
    }
}
