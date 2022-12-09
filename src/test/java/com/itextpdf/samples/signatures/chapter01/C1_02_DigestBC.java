package com.itextpdf.samples.signatures.chapter01;

import java.io.File;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.Provider;
import java.util.Arrays;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class C1_02_DigestBC {
    public static final String DEST = "./target/test/resources/signatures/chapter01/";

    public static final BouncyCastleProvider PROVIDER = new BouncyCastleProvider();

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
            "Digest: a8b64babd0aca91a59bdbb7761b421d4f2bb38280d3a75ba0f21f2bebc45583d446c" +
            "598660c94ce680c47d19c30783a7\n" +
            "Is the password 'password'? true\n" +
            "Is the password 'secret'? false\n" +
            "Digest using SHA-512: 64\n" +
            "Digest: b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b1d7" +
            "785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86\n" +
            "Is the password 'password'? true\n" +
            "Is the password 'secret'? false\n" +
            "Digest using RIPEMD128: 16\n" +
            "Digest: c9c6d316d6dc4d952a789fd4b8858ed7\n" +
            "Is the password 'password'? true\n" +
            "Is the password 'secret'? false\n" +
            "Digest using RIPEMD160: 20\n" +
            "Digest: 2c08e8f5884750a7b99f6f2f342fc638db25ff31\n" +
            "Is the password 'password'? true\n" +
            "Is the password 'secret'? false\n" +
            "Digest using RIPEMD256: 32\n" +
            "Digest: f94cf96c79103c3ccad10d308c02a1db73b986e2c48962e96ecd305e0b80ef1b\n" +
            "Is the password 'password'? true\n" +
            "Is the password 'secret'? false\n";

    protected byte[] digest;
    protected MessageDigest messageDigest;

    protected C1_02_DigestBC(String password, String algorithm, Provider provider) throws GeneralSecurityException,
            UnsupportedEncodingException {
        if (provider == null) {
            messageDigest = MessageDigest.getInstance(algorithm);
        } else {

            // BouncyCastle provider can be initialized in another way
            // by using Security.addProvider(Provider provider) method
            messageDigest = MessageDigest.getInstance(algorithm, provider);
        }
        digest = messageDigest.digest(password.getBytes("UTF-8"));
    }

    public static C1_02_DigestBC getInstance(String password, String algorithm) throws GeneralSecurityException,
            UnsupportedEncodingException {
        return new C1_02_DigestBC(password, algorithm, PROVIDER);
    }

    public static void main(String[] args) throws Exception {
        File file = new File(DEST);
        file.mkdirs();

        testAll();
    }

    public static void testAll() throws Exception {
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

    public static void showTest(String algorithm) throws Exception {
        C1_02_DigestBC app = getInstance("password", algorithm);
        System.out.println("Digest using " + algorithm + ": " + app.getDigestSize());
        System.out.println("Digest: " + app.getDigestAsHexString());
        System.out.println("Is the password 'password'? " + app.checkPassword("password"));
        System.out.println("Is the password 'secret'? " + app.checkPassword("secret"));
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
