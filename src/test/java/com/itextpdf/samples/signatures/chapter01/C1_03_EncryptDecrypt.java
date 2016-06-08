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

import javax.crypto.Cipher;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.X509Certificate;

import org.junit.Test;
import org.junit.experimental.categories.Category;
import static org.junit.Assert.fail;

@Category(SampleTest.class)
public class C1_03_EncryptDecrypt extends SignatureTest {
    public static final  String expectedOutput = "Let's encrypt 'secret message' with a public key\n" +
            "Encrypted message: 117831320649a4b0f420466c45a2368cae6d5edf8a99e9d04c69e8a6f63c8616776406928a11b9f0e01101d1e5d90558f99152c91fd175fb6bb7b1282e6b2d2c955d1596d923c09597a6de3b15aa6f0ec720f0958a5b8180ad4042121dadef835804f653846a06280e9661e2dcf4eb89afb3fc3b61e9ccccc39cd8ca3714145e48cc9aa4013f13e3407a669117d95b173a368fab7fac1678c06c68fc79c5019718e52119cee1355c3fae7a47a8916789b0797fef9c94bca99753fd2f33d1e0849128a9c3a3e26bc09199e66d8831294b97ccdf7a5b6d37857ed1e55da946f23d4f87abc48f1b9e72e6e65f15843f24cf5784b619eb25acd19344729e37481779\n" +
            "Let's decrypt it with the corresponding private key\n" +
            "secret message\n" +
            "You can also encrypt the message with a private key\n" +
            "Encrypted message: 289c63ccb0dc49a2e9f0f3e0dcabcd036f503f05abbe1dc110ed8364856e04a875c7c0adef9b407c40bb77921540617aa85693e13b3fefe88b2ab9449b3a6fd81bce5ee3e7d2b81f0cf0593da83c94f8e203cc8690022df0e6c8ebb0c001c5241ada3033e4b9d1060ef167b4b6b0f850b4324fb8b4b48dee1691214ea435e81f825f036e12512b283c7a08e2d9e24c2910c2989797a70943701450eeda86d968d432829ee0764b93c636c988de7b9dca198a8150a31f8cb2fedb498b7908abec59f601ce47b1ab0deb632b4a6f904b5e969c5a70cb50c749ea2467f0bcd504d85a7d1a477e29fc4767695e00c141f82ec75ede6d0c342182f7d9d8f72faa3aec\n" +
            "Now you need the public key to decrypt it\n" +
            "secret message\n";
    protected static final String KEYSTORE = "./src/test/resources/encryption/ks";
    protected static final String PASSWORD = "password";
    protected KeyStore ks;

    public static void main(String[] args) throws GeneralSecurityException, IOException {
        C1_03_EncryptDecrypt app = new C1_03_EncryptDecrypt();
        app.initKeyStore(KEYSTORE, PASSWORD);
        Key publicKey = app.getPublicKey("demo");
        Key privateKey = app.getPrivateKey("demo", "password");

        System.out.println("Let's encrypt 'secret message' with a public key");
        byte[] encrypted = app.encrypt(publicKey, "secret message");
        System.out.println("Encrypted message: " + new BigInteger(1, encrypted).toString(16));
        System.out.println("Let's decrypt it with the corresponding private key");
        String decrypted = app.decrypt(privateKey, encrypted);
        System.out.println(decrypted);

        System.out.println("You can also encrypt the message with a private key");
        encrypted = app.encrypt(privateKey, "secret message");
        System.out.println("Encrypted message: " + new BigInteger(1, encrypted).toString(16));
        System.out.println("Now you need the public key to decrypt it");
        decrypted = app.decrypt(publicKey, encrypted);
        System.out.println(decrypted);
    }

    public void initKeyStore(String keystore, String ks_pass) throws GeneralSecurityException, IOException {
        ks = KeyStore.getInstance(KeyStore.getDefaultType());
        ks.load(new FileInputStream(keystore), ks_pass.toCharArray());
    }

    public X509Certificate getCertificate(String alias) throws KeyStoreException {
        return (X509Certificate) ks.getCertificate(alias);
    }

    public Key getPublicKey(String alias) throws GeneralSecurityException, IOException {
        return getCertificate(alias).getPublicKey();
    }

    public Key getPrivateKey(String alias, String pk_pass) throws GeneralSecurityException, IOException {
        return ks.getKey(alias, pk_pass.toCharArray());
    }

    public byte[] encrypt(Key key, String message) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] cipherData = cipher.doFinal(message.getBytes());
        return cipherData;
    }

    public String decrypt(Key key, byte[] message) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] cipherData = cipher.doFinal(message);
        return new String(cipherData);
    }

    @Test
    public void runTest() throws GeneralSecurityException, IOException, InterruptedException {
        new File("./target/test/resources/signatures/chapter01/").mkdirs();
        setupSystemOutput();
        C1_03_EncryptDecrypt.main(null);
        String sysOut = getSystemOutput();

        String[] outputLines = sysOut.split("\n");
        String[] expectedLines = expectedOutput.split("\n");

        for (int i = 0; i < outputLines.length; ++i) {
            String line = outputLines[i];
            if (!line.startsWith("Encrypted message: ") && !line.trim().equals(expectedLines[i].trim())) {
                String error = "Unexpected output at line %d.\nExpected: %s\ngot: %s";
                fail(String.format(error, i + 1, expectedLines[i], outputLines[i]));
            }
        }
    }
}