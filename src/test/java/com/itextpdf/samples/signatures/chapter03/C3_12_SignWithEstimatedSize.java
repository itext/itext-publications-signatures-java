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

import com.itextpdf.kernel.geom.Rectangle;
import com.itextpdf.signatures.*;
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
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Properties;

import static org.junit.Assert.fail;

@Ignore("Put property file with valid data")
@Category(SampleTest.class)
public class C3_12_SignWithEstimatedSize extends C3_01_SignWithCAcert {
    public static final String SRC = "./src/test/resources/pdfs/hello.pdf";
    public static final String DEST = "./target/test/resources/signatures/chapter03/hello_estimated.pdf";
    public static final String expectedOutput = "";

    public static void main(String[] args) throws IOException, GeneralSecurityException {
        Properties properties = new Properties();
        properties.load(new FileInputStream("./src/test/resources/encryption/signkey.properties"));
        String path = properties.getProperty("PRIVATE");
        char[] pass = properties.getProperty("PASSWORD").toCharArray();
        String tsaUrl = properties.getProperty("TSAURL");
        String tsaUser = properties.getProperty("TSAUSERNAME");
        String tsaPass = properties.getProperty("TSAPASSWORD");

        BouncyCastleProvider provider = new BouncyCastleProvider();
        Security.addProvider(provider);
        KeyStore ks = KeyStore.getInstance("pkcs12", provider.getName());
        ks.load(new FileInputStream(path), pass);
        String alias = ks.aliases().nextElement();
        PrivateKey pk = (PrivateKey) ks.getKey(alias, pass);
        Certificate[] chain = ks.getCertificateChain(alias);
        IOcspClient ocspClient = new OcspClientBouncyCastle(null);
        ITSAClient tsaClient = new TSAClientBouncyCastle(tsaUrl, tsaUser, tsaPass);
        C3_12_SignWithEstimatedSize app = new C3_12_SignWithEstimatedSize();
        boolean succeeded = false;
        int estimatedSize = 1000;
        while (!succeeded) {
            try {
                System.out.println("Attempt: " + estimatedSize + " bytes");
                app.sign(SRC, DEST, chain, pk, DigestAlgorithms.SHA256, provider.getName(), PdfSigner.CryptoStandard.CMS, "Test", "Ghent",
                        null, ocspClient, null, estimatedSize);
                succeeded = true;
                System.out.println("Succeeded!");
            } catch (IOException ioe) {
                System.out.println("Not succeeded: " + ioe.getMessage());
                estimatedSize += 50;
            }
        }
    }

    @Test
    public void runTest() throws IOException, InterruptedException, GeneralSecurityException {
        new File("./target/test/resources/signatures/chapter03/").mkdirs();
        setupSystemOutput();
        C3_12_SignWithEstimatedSize.main(null);
        String sysOut = getSystemOutput();

        if (!sysOut.equals(expectedOutput)) {
            fail("Unexpected output.");
        }
        String[] resultFiles = new String[]{"hello_estimated.pdf"};

        String destPath = String.format(outPath, "chapter03");
        String comparePath = String.format(cmpPath, "chapter03");

        String[] errors = new String[resultFiles.length];
        boolean error = false;

        HashMap<Integer, List<Rectangle>> ignoredAreas = new HashMap<Integer, List<Rectangle>>() { {
            put(1, Arrays.asList(new Rectangle(36, 648, 200, 100)));
        }};

        for (int i = 0; i < resultFiles.length; i++) {
            String resultFile = resultFiles[i];
            String fileErrors = checkForErrors(destPath + resultFile, comparePath + "cmp_" + resultFile, destPath, ignoredAreas);
            if (fileErrors != null) {
                errors[i] = fileErrors;
                error = true;
            }
        }

        if (error) {
            fail(accumulateErrors(errors));
        }
    }
}
