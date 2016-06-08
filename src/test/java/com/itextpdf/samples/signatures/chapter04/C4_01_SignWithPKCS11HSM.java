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
import com.itextpdf.kernel.geom.Rectangle;
import com.itextpdf.kernel.pdf.PdfReader;
import com.itextpdf.samples.SignatureTest;
import com.itextpdf.signatures.BouncyCastleDigest;
import com.itextpdf.signatures.CertificateUtil;
import com.itextpdf.signatures.ICrlClient;
import com.itextpdf.signatures.CrlClientOnline;
import com.itextpdf.signatures.DigestAlgorithms;
import com.itextpdf.signatures.IExternalDigest;
import com.itextpdf.signatures.IExternalSignature;
import com.itextpdf.signatures.IOcspClient;
import com.itextpdf.signatures.OcspClientBouncyCastle;
import com.itextpdf.signatures.PdfSignatureAppearance;
import com.itextpdf.signatures.PdfSigner;
import com.itextpdf.signatures.PrivateKeySignature;
import com.itextpdf.signatures.ITSAClient;
import com.itextpdf.signatures.TSAClientBouncyCastle;
import com.itextpdf.test.annotations.type.SampleTest;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Properties;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.experimental.categories.Category;

@Ignore("Put property file with valid data")
@Category(SampleTest.class)
public class C4_01_SignWithPKCS11HSM extends SignatureTest {
    public static final String SRC = "./src/test/resources/pdfs/hello.pdf";
    public static final String DEST = "./target/test/resources/signatures/chapter04/hello_hsm.pdf";
    public static final String PROPS = "./src/test/resources/encryption/signkey.properties";

    public void sign(String src, String dest,
                     Certificate[] chain, PrivateKey pk,
                     String digestAlgorithm, String provider, PdfSigner.CryptoStandard subfilter,
                     String reason, String location,
                     Collection<ICrlClient> crlList,
                     IOcspClient ocspClient,
                     ITSAClient tsaClient,
                     int estimatedSize)
            throws GeneralSecurityException, IOException {
        // Creating the reader and the signer
        PdfReader reader = new PdfReader(src);
        PdfSigner signer = new PdfSigner(reader, new FileOutputStream(dest), false);
        // Creating the appearance
        PdfSignatureAppearance appearance = signer.getSignatureAppearance()
                .setReason(reason)
                .setLocation(location)
                .setReuseAppearance(false);
        Rectangle rect = new Rectangle(36, 648, 200, 100);
        appearance
                .setPageRect(rect)
                .setPageNumber(1);
        signer.setFieldName("sig");
        // Creating the signature
        IExternalSignature pks = new PrivateKeySignature(pk, digestAlgorithm, provider);
        IExternalDigest digest = new BouncyCastleDigest();
        signer.signDetached(digest, pks, chain, crlList, ocspClient, tsaClient, estimatedSize, subfilter);
    }

    public static void main(String[] args) throws IOException, GeneralSecurityException {
        Properties properties = new Properties();
        properties.load(new FileInputStream(PROPS));
        char[] pass = properties.getProperty("PASSWORD").toCharArray();
        String pkcs11cfg = properties.getProperty("PKCS11CFG");

        BouncyCastleProvider providerBC = new BouncyCastleProvider();
        Security.addProvider(providerBC);
        FileInputStream fis = new FileInputStream(pkcs11cfg);
        Provider providerPKCS11 = new SunPKCS11(fis);
        Security.addProvider(providerPKCS11);

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
        C4_01_SignWithPKCS11HSM app = new C4_01_SignWithPKCS11HSM();
        app.sign(SRC, DEST, chain, pk, DigestAlgorithms.SHA256, providerPKCS11.getName(), PdfSigner.CryptoStandard.CMS,
                "HSM test", "Ghent", crlList, ocspClient, tsaClient, 0);
    }

    /**
     * In this test we only run the sample. If no exception were thrown - test succeeds.
     */
    @Test
    public void runTest() throws GeneralSecurityException, IOException, InterruptedException {
        new File("./target/test/resources/signatures/chapter04/").mkdirs();
        C4_01_SignWithPKCS11HSM.main(null);
    }
}
