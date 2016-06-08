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
package com.itextpdf.samples.signatures.chapter03;

import com.itextpdf.samples.SignatureTest;
import com.itextpdf.signatures.CertificateUtil;
import com.itextpdf.test.annotations.type.SampleTest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.experimental.categories.Category;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Properties;

import static org.junit.Assert.fail;

@Ignore("Put property file with valid data")
@Category(SampleTest.class)
public class C3_02_GetCrlUrl extends SignatureTest {
    public static final  String expectedOutput = "";

    public static void main(String[] args) throws IOException, GeneralSecurityException {
        Properties properties = new Properties();
        properties.load(new FileInputStream("./src/test/resources/encryption/signkey.properties"));
        String path = properties.getProperty("PRIVATE");
        char[] pass = properties.getProperty("PASSWORD").toCharArray();


        BouncyCastleProvider provider = new BouncyCastleProvider();
        Security.addProvider(provider);
        KeyStore ks = KeyStore.getInstance("pkcs12", provider.getName());
        ks.load(new FileInputStream(path), pass);
        String alias = ks.aliases().nextElement();
        Certificate[] chain = ks.getCertificateChain(alias);
        for (int i = 0; i < chain.length; i++) {
            X509Certificate cert = (X509Certificate) chain[i];
            System.out.println(String.format("[%s] %s", i, cert.getSubjectDN()));
            System.out.println(CertificateUtil.getCRLURL(cert));
        }
    }

    @Test
    public void runTest() throws IOException, InterruptedException, GeneralSecurityException {
        new File("./target/test/resources/signatures/chapter03/").mkdirs();
        setupSystemOutput();
        C3_02_GetCrlUrl.main(null);
        String sysOut = getSystemOutput();

        if (!sysOut.equals(expectedOutput)) {
            fail("Unexpected output.");
        }
    }
}