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
import sun.security.pkcs11.wrapper.CK_C_INITIALIZE_ARGS;
import sun.security.pkcs11.wrapper.CK_TOKEN_INFO;
import sun.security.pkcs11.wrapper.PKCS11;
import sun.security.pkcs11.wrapper.PKCS11Exception;
import com.itextpdf.signatures.CertificateUtil;
import com.itextpdf.signatures.ICrlClient;
import com.itextpdf.signatures.CrlClientOnline;
import com.itextpdf.signatures.DigestAlgorithms;
import com.itextpdf.signatures.IOcspClient;
import com.itextpdf.signatures.OcspClientBouncyCastle;
import com.itextpdf.signatures.PdfSigner;
import com.itextpdf.signatures.ITSAClient;
import com.itextpdf.signatures.TSAClientBouncyCastle;
import com.itextpdf.test.annotations.type.SampleTest;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import static org.junit.Assert.fail;

@Ignore("Put right property file with valid data and right dll path")
@Category(SampleTest.class)
public class C4_02_SignWithPKCS11USB extends C4_01_SignWithPKCS11HSM {
    public static final String SRC = "./src/test/resources/pdfs/hello.pdf";
    public static final String DEST = "./target/test/resources/signatures/chapter04/hello_token.pdf";
    public static final String DLL = "c:/windows/system32/dkck201.dll";

    public static void main(String[] args) throws IOException, GeneralSecurityException {
        Properties properties = new Properties();
        properties.load(new FileInputStream("./src/test/resources/encryption/signkey.properties"));
        char[] pass = properties.getProperty("PASSWORD").toCharArray();

        String config = "name=ikey4000\n" +
                "library=" + DLL + "\n" +
                "slotListIndex = " + getSlotsWithTokens(DLL)[0];
        ByteArrayInputStream bais = new ByteArrayInputStream(config.getBytes());
        Provider providerPKCS11 = new SunPKCS11(bais);
        Security.addProvider(providerPKCS11);
        System.out.println(providerPKCS11.getName());
        BouncyCastleProvider providerBC = new BouncyCastleProvider();
        Security.addProvider(providerBC);

        KeyStore ks = KeyStore.getInstance("PKCS11");
        ks.load(null, pass);
        String alias = ks.aliases().nextElement();
        PrivateKey pk = (PrivateKey) ks.getKey(alias, pass);
        Certificate[] chain = ks.getCertificateChain(alias);
        IOcspClient ocspClient = new OcspClientBouncyCastle(null);
        ITSAClient tsaClient = null;
        for (int i = 0; i < chain.length; i++) {
            X509Certificate cert = (X509Certificate) chain[i];
            String tsaUrl = CertificateUtil.getTSAURL(cert);
            if (tsaUrl != null) {
                tsaClient = new TSAClientBouncyCastle(tsaUrl);
                break;
            }
        }
        List<ICrlClient> crlList = new ArrayList<ICrlClient>();
        crlList.add(new CrlClientOnline(chain));
        C4_02_SignWithPKCS11USB app = new C4_02_SignWithPKCS11USB();
        app.sign(SRC, DEST, chain, pk, DigestAlgorithms.SHA256, providerPKCS11.getName(), PdfSigner.CryptoStandard.CMS,
                "Test", "Ghent", crlList, ocspClient, tsaClient, 0);
    }

    public static long[] getSlotsWithTokens(String libraryPath) throws IOException {
        CK_C_INITIALIZE_ARGS initArgs = new CK_C_INITIALIZE_ARGS();
        String functionList = "C_GetFunctionList";

        initArgs.flags = 0;
        PKCS11 tmpPKCS11 = null;
        long[] slotList = null;
        try {
            try {
                tmpPKCS11 = PKCS11.getInstance(libraryPath, functionList, initArgs, false);
            } catch (IOException ex) {
                ex.printStackTrace();
                throw ex;
            }
        } catch (PKCS11Exception e) {
            try {
                initArgs = null;
                tmpPKCS11 = PKCS11.getInstance(libraryPath, functionList, initArgs, true);
            } catch (IOException ex) {
                ex.printStackTrace();
            } catch (PKCS11Exception ex) {
                ex.printStackTrace();
            }
        }

        try {
            slotList = tmpPKCS11.C_GetSlotList(true);

            for (long slot : slotList) {
                CK_TOKEN_INFO tokenInfo = tmpPKCS11.C_GetTokenInfo(slot);
                System.out.println("slot: " + slot + "\nmanufacturerID: "
                        + String.valueOf(tokenInfo.manufacturerID) + "\nmodel: "
                        + String.valueOf(tokenInfo.model));
            }
        } catch (PKCS11Exception ex) {
            ex.printStackTrace();
        } catch (Throwable t) {
            t.printStackTrace();
        }

        return slotList;
    }

    @Test
    public void runTest() throws IOException, InterruptedException, GeneralSecurityException {
        new File("./target/test/resources/signatures/chapter04/").mkdirs();
        C4_02_SignWithPKCS11USB.main(null);

        String[] resultFiles = new String[]{"hello_token.pdf"};

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
