/*

    This file is part of the iText (R) project.
    Copyright (c) 1998-2016 iText Group NV

*/

/*
 * This class is part of the white paper entitled
 * "Digital Signatures for PDF documents"
 * written by Bruno Lowagie
 *
 * For more info, go to: http://itextpdf.com/learn
 */
package com.itextpdf.samples.signatures.chapter01;

import com.itextpdf.samples.SignatureTest;
import com.itextpdf.test.annotations.type.SampleTest;

import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Arrays;

import org.junit.Ignore;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import static org.junit.Assert.fail;

@Ignore("The result differs on different machines")
@Category(SampleTest.class)
public class C1_01_DigestDefault extends SignatureTest {
    public static final String expectedOutput = "Digest using MD5: 16\n" +
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
            "Digest: a8b64babd0aca91a59bdbb7761b421d4f2bb38280d3a75ba0f21f2bebc45583d446c598660c94ce680c47d19c30783a7\n" +
            "Is the password 'password'? true\n" +
            "Is the password 'secret'? false\n" +
            "Digest using SHA-512: 64\n" +
            "Digest: b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86\n" +
            "Is the password 'password'? true\n" +
            "Is the password 'secret'? false\n" +
            "RIPEMD128 MessageDigest not available\n" +
            "RIPEMD160 MessageDigest not available\n" +
            "RIPEMD256 MessageDigest not available\n";

    protected byte[] digest;
    protected MessageDigest md;

    public C1_01_DigestDefault() {
        // this constructor is implemented only for junit testing reasons
        // and does nothing
    }

    protected C1_01_DigestDefault(String password, String algorithm, String provider) throws GeneralSecurityException {
        if (provider == null)
            md = MessageDigest.getInstance(algorithm);
        else
            md = MessageDigest.getInstance(algorithm, provider);
        digest = md.digest(password.getBytes());
    }

    public static C1_01_DigestDefault getInstance(String password, String algorithm) throws GeneralSecurityException {
        return new C1_01_DigestDefault(password, algorithm, null);
    }

    public static void showTest(String algorithm) {
        try {
            C1_01_DigestDefault app = getInstance("password", algorithm);
            System.out.println("Digest using " + algorithm + ": " + app.getDigestSize());
            System.out.println("Digest: " + app.getDigestAsHexString());
            System.out.println("Is the password 'password'? " + app.checkPassword("password"));
            System.out.println("Is the password 'secret'? " + app.checkPassword("secret"));
        } catch (GeneralSecurityException e) {
            System.out.println(e.getMessage());
        }
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

    public static void main(String[] args) {
        testAll();
    }

    public int getDigestSize() {
        return digest.length;
    }

    public String getDigestAsHexString() {
        return new BigInteger(1, digest).toString(16);
    }

    public boolean checkPassword(String password) {
        return Arrays.equals(digest, md.digest(password.getBytes()));
    }

    @Test
    public void runTest() throws GeneralSecurityException, IOException, InterruptedException {
        new File("./target/test/resources/signatures/chapter01/").mkdirs();
        setupSystemOutput();
        C1_01_DigestDefault.main(null);
        String sysOut = getSystemOutput();

        String[] outputLines = sysOut.split("\n");
        String[] expectedLines = expectedOutput.split("\n");

        for (int i = 0; i < outputLines.length; ++i) {
            String line = outputLines[i];
            if (!line.startsWith("Digest: ") && !line.trim().equals(expectedLines[i].trim())) {
                String error = "Unexpected output at line %d.\nExpected: %s\ngot: %s";
                fail(String.format(error, i + 1, expectedLines[i], outputLines[i]));
            }
        }
    }
}
