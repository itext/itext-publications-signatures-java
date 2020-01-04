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

public class C1_03_EncryptDecrypt {
    public static final String DEST = "./target/test/resources/signatures/chapter01/";

    protected static final String KEYSTORE = "./src/test/resources/encryption/ks";

    protected static final String PASSWORD = "password";
    protected KeyStore ks;

    public static void main(String[] args) throws Exception {
        File file = new File(DEST);
        file.mkdirs();

        encryptDecrypt();
    }

    public static void encryptDecrypt() throws GeneralSecurityException, IOException {
        C1_03_EncryptDecrypt app = new C1_03_EncryptDecrypt();
        app.initKeyStore(KEYSTORE, PASSWORD);
        Key publicKey = app.getPublicKey("demo");
        Key privateKey = app.getPrivateKey("demo", "password");

        // Encrypt the message with the public key and then decrypt it with the private key
        System.out.println("Let's encrypt 'secret message' with a public key");
        byte[] encrypted = app.encrypt(publicKey, "secret message");
        System.out.println("Encrypted message: " + app.getDigestAsHexString(encrypted));
        System.out.println("Let's decrypt it with the corresponding private key");
        String decrypted = app.decrypt(privateKey, encrypted);
        System.out.println(decrypted);

        // Encrypt the message with the private key and then decrypt it with the public key
        System.out.println("You can also encrypt the message with a private key");
        encrypted = app.encrypt(privateKey, "secret message");
        System.out.println("Encrypted message: " + app.getDigestAsHexString(encrypted));
        System.out.println("Now you need the public key to decrypt it");
        decrypted = app.decrypt(publicKey, encrypted);
        System.out.println(decrypted);
    }

    private void initKeyStore(String keystore, String ks_pass) throws GeneralSecurityException, IOException {
        ks = KeyStore.getInstance(KeyStore.getDefaultType());
        ks.load(new FileInputStream(keystore), ks_pass.toCharArray());
    }

    private String getDigestAsHexString(byte[] digest) {
        return new BigInteger(1, digest).toString(16);
    }

    private X509Certificate getCertificate(String alias) throws KeyStoreException {
        return (X509Certificate) ks.getCertificate(alias);
    }

    private Key getPublicKey(String alias) throws GeneralSecurityException, IOException {
        return getCertificate(alias).getPublicKey();
    }

    private Key getPrivateKey(String alias, String pk_pass) throws GeneralSecurityException, IOException {
        return ks.getKey(alias, pk_pass.toCharArray());
    }

    // This method encrypts the message (using RSA algorithm) with the key, got as the 1st argument
    public byte[] encrypt(Key key, String message) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] cipherData = cipher.doFinal(message.getBytes());
        return cipherData;
    }

    // This method decrypts the message (using RSA algorithm) with the key, got as the 1st argument
    public String decrypt(Key key, byte[] message) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] cipherData = cipher.doFinal(message);
        return new String(cipherData);
    }
}
