/*
    This file is part of the iText (R) project.
    Copyright (c) 1998-2020 iText Group NV
    Authors: iText Software.

    For more information, please contact iText Software at this address:
    sales@itextpdf.com
 */
/*
 * This class is part of the white paper entitled
 * "Digital Signatures for PDF documents"
 * written by Bruno Lowagie
 *
 * For more info, go to: http://itextpdf.com/learn
 */
package com.itextpdf.samples.signatures.chapter01;

import java.io.File;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Arrays;

public class C1_01_DigestDefault {
    public static final String DEST = "./target/test/resources/signatures/chapter01/";

    public static final String EXPECTED_OUTPUT = "Digest using MD5: 16\n" +
            "Digest: 5f4dcc3b5aa765d61d8327deb882cf99\n" +
            "Is the password 'password'? true\n" +
            "Is the password 'secret'? false\n" +
            "Digest using SHA-1: 20\n" +
            "Digest: 5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8\n" +
            "Is the password 'password'? true\n" +
            "Is the password 'secret'? false\n" +
            "Digest using SHA-224: 28\n" +
            "Digest: d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01\n" +
            "Is the password 'password'? true\n" +
            "Is the password 'secret'? false\n" +
            "Digest using SHA-256: 32\n" +
            "Digest: 5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8\n" +
            "Is the password 'password'? true\n" +
            "Is the password 'secret'? false\n" +
            "Digest using SHA-384: 48\n" +
            "Digest: a8b64babd0aca91a59bdbb7761b421d4f2bb38280d3a75ba0f21f2bebc4558" +
            "3d446c598660c94ce680c47d19c30783a7\n" +
            "Is the password 'password'? true\n" +
            "Is the password 'secret'? false\n" +
            "Digest using SHA-512: 64\n" +
            "Digest: b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b" +
            "1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86\n" +
            "Is the password 'password'? true\n" +
            "Is the password 'secret'? false\n" +
            "RIPEMD128 MessageDigest not available\n" +
            "RIPEMD160 MessageDigest not available\n" +
            "RIPEMD256 MessageDigest not available\n";

    protected byte[] digest;
    protected MessageDigest messageDigest;

    protected C1_01_DigestDefault(String password, String algorithm, String provider) throws GeneralSecurityException,
            UnsupportedEncodingException {
        if (provider == null) {
            messageDigest = MessageDigest.getInstance(algorithm);
        } else {
            messageDigest = MessageDigest.getInstance(algorithm, provider);
        }
        digest = messageDigest.digest(password.getBytes("UTF-8"));
    }

    public static C1_01_DigestDefault getInstance(String password, String algorithm) throws GeneralSecurityException,
            UnsupportedEncodingException {
        return new C1_01_DigestDefault(password, algorithm, null);
    }

    public static void main(String[] args) {
        File file = new File(DEST);
        file.mkdirs();

        testAll();
    }

    public static void testAll() {
        showTest("MD5");
        showTest("SHA-1");
        showTest("SHA-224");
        showTest("SHA-256");
        showTest("SHA-384");
        showTest("SHA-512");
        showTest("RIPEMD128");
        showTest("RIPEMD160");
        showTest("RIPEMD256");
    }

    public static void showTest(String algorithm) {
        try {
            C1_01_DigestDefault app = getInstance("password", algorithm);
            System.out.println("Digest using " + algorithm + ": " + app.getDigestSize());
            System.out.println("Digest: " + app.getDigestAsHexString());
            System.out.println("Is the password 'password'? " + app.checkPassword("password"));
            System.out.println("Is the password 'secret'? " + app.checkPassword("secret"));
        } catch (Exception exc) {
            System.out.println(exc.getMessage());
        }
    }

    public int getDigestSize() {
        return digest.length;
    }

    public String getDigestAsHexString() {
        return new BigInteger(1, digest).toString(16);
    }

    /* This method checks if the digest of the password is equal
     * to the digest of the text line which is passed as argument
     */
    public boolean checkPassword(String password) {
        return Arrays.equals(digest, messageDigest.digest(password.getBytes()));
    }
}
