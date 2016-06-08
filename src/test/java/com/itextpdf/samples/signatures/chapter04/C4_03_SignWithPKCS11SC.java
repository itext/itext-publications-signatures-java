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
package com.itextpdf.samples.signatures.chapter04;

import sun.security.pkcs11.SunPKCS11;
import com.itextpdf.signatures.ICrlClient;
import com.itextpdf.signatures.CrlClientOnline;
import com.itextpdf.signatures.DigestAlgorithms;
import com.itextpdf.signatures.IOcspClient;
import com.itextpdf.signatures.OcspClientBouncyCastle;
import com.itextpdf.signatures.PdfSigner;
import com.itextpdf.test.annotations.type.SampleTest;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import static org.junit.Assert.fail;

@Ignore("Put right property file with valid data and right dll path")
@Category(SampleTest.class)
public class C4_03_SignWithPKCS11SC extends C4_02_SignWithPKCS11USB {
    public static final String SRC = "./src/test/resources/pdfs/hello.pdf";
    public static final String DEST = "./target/test/resources/signatures/chapter04/hello_smartcard_%s.pdf";
    public static final String DLL = "c:/windows/system32/beidpkcs11.dll";

    public static void main(String[] args) throws IOException, GeneralSecurityException {
        String config = "name=beid\n" +
                "library=" + DLL + "\n" +
                "slotListIndex = " + getSlotsWithTokens(DLL)[0];
        ByteArrayInputStream bais = new ByteArrayInputStream(config.getBytes());
        Provider providerPKCS11 = new SunPKCS11(bais);
        Security.addProvider(providerPKCS11);
        BouncyCastleProvider providerBC = new BouncyCastleProvider();
        Security.addProvider(providerBC);
        KeyStore ks = KeyStore.getInstance("PKCS11");
        ks.load(null, null);
        Enumeration<String> aliases = ks.aliases();
        while (aliases.hasMoreElements()) {
            System.out.println(aliases.nextElement());
        }
        smartcardsign(providerPKCS11.getName(), ks, "Authentication");
        smartcardsign(providerPKCS11.getName(), ks, "Signature");
    }

    public static void smartcardsign(String provider, KeyStore ks, String alias) throws GeneralSecurityException, IOException {
        PrivateKey pk = (PrivateKey) ks.getKey(alias, null);
        Certificate[] chain = ks.getCertificateChain(alias);
        IOcspClient ocspClient = new OcspClientBouncyCastle(null);
        List<ICrlClient> crlList = new ArrayList<ICrlClient>();
        crlList.add(new CrlClientOnline(chain));
        C4_03_SignWithPKCS11SC app = new C4_03_SignWithPKCS11SC();
        app.sign(SRC, String.format(DEST, alias), chain, pk, DigestAlgorithms.SHA256, provider, PdfSigner.CryptoStandard.CMS,
                "Test", "Ghent", crlList, ocspClient, null, 0);
    }

    @Test
    public void runTest() throws IOException, InterruptedException, GeneralSecurityException {
        new File("./target/test/resources/signatures/chapter04/").mkdirs();
        C4_03_SignWithPKCS11SC.main(null);

        String[] resultFiles = new String[]{ "hello_smartcard_Authentication.pdf", "hello_smartcard_Signature.pdf" };

        String destPath = String.format(outPath, "chapter04");
        String comparePath = String.format(cmpPath, "chapter04");

        String[] errors = new String[resultFiles.length];
        boolean error = false;

//        HashMap<Integer, List<Rectangle>> ignoredAreas = new HashMap<Integer, List<Rectangle>>() { {
//            put(1, Arrays.asList(new Rectangle(36, 648, 200, 100)));
//        }};

        for (int i = 0; i < resultFiles.length; i++) {
            String resultFile = resultFiles[i];
            String fileErrors = checkForErrors(destPath + resultFile, comparePath + "cmp_" + resultFile, destPath, /*ignoredAreas*/ null);
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
