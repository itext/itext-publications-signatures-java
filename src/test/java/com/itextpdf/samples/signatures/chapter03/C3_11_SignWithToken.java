/*
    This file is part of the iText (R) project.
    Copyright (c) 1998-2019 iText Group NV
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
package com.itextpdf.samples.signatures.chapter03;

import java.io.File;
import java.io.FileOutputStream;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import com.itextpdf.kernel.geom.Rectangle;
import com.itextpdf.kernel.pdf.PdfReader;
import com.itextpdf.kernel.pdf.StampingProperties;
import com.itextpdf.signatures.BouncyCastleDigest;
import com.itextpdf.signatures.CertificateUtil;
import com.itextpdf.signatures.CrlClientOnline;
import com.itextpdf.signatures.DigestAlgorithms;
import com.itextpdf.signatures.ICrlClient;
import com.itextpdf.signatures.IExternalDigest;
import com.itextpdf.signatures.IExternalSignature;
import com.itextpdf.signatures.IOcspClient;
import com.itextpdf.signatures.ITSAClient;
import com.itextpdf.signatures.OcspClientBouncyCastle;
import com.itextpdf.signatures.PdfSignatureAppearance;
import com.itextpdf.signatures.PdfSigner;
import com.itextpdf.signatures.PrivateKeySignature;
import com.itextpdf.signatures.TSAClientBouncyCastle;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class C3_11_SignWithToken {
    public static final String SRC = "./src/test/resources/pdfs/hello.pdf";
    public static final String DEST = "./target/test/resources/signatures/chapter03/";

    public static final String[] RESULT_FILES = new String[] {
            "hello_token.pdf"
    };

    public static void main(String[] args) throws IOException, GeneralSecurityException {
        File file = new File(DEST);
        file.mkdirs();

        BouncyCastleProvider providerBC = new BouncyCastleProvider();
        Security.addProvider(providerBC);

        /* This isn’t really necessary to explicitly add the instance of SunMSCAPI to the providers list,
         * because if this provider is available in JDK, then it's expected that it is already registered.
         * However, SunMSCAPI is a part of the sun.* packages, which are not part of the supported,
         * public interface. If this part of code can be complied without errors, then your JDK
         * still supports SunMSCAPI.
         */
//        SunMSCAPI providerMSCAPI = new SunMSCAPI();
//        Security.addProvider(providerMSCAPI);

        KeyStore ks = KeyStore.getInstance("Windows-MY");

        /* Because of creating a Keystore instance using the parameter “Windows-MY”,
         * all the signing operations are passed to the Microsoft CryptoAPI.
         * That is why the stream and password are null.
         */
        ks.load(null, null);
        String alias = "Bruno Lowagie";
        PrivateKey pk = (PrivateKey) ks.getKey(alias, null);
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

        // This provider name can be used only if JDK supports it.
        String mscapiName = "SunMSCAPI";
        new C3_11_SignWithToken().sign(SRC, DEST + RESULT_FILES[0], chain, pk, DigestAlgorithms.SHA384,
                mscapiName, PdfSigner.CryptoStandard.CMS, "Test", "Ghent",
                crlList, ocspClient, tsaClient, 0);
    }

    public void sign(String src, String dest, Certificate[] chain, PrivateKey pk,
            String digestAlgorithm, String provider, PdfSigner.CryptoStandard subfilter,
            String reason, String location, Collection<ICrlClient> crlList,
            IOcspClient ocspClient, ITSAClient tsaClient, int estimatedSize)
            throws GeneralSecurityException, IOException {
        PdfReader reader = new PdfReader(src);
        PdfSigner signer = new PdfSigner(reader, new FileOutputStream(dest), new StampingProperties());

        // Create the signature appearance
        Rectangle rect = new Rectangle(36, 648, 200, 100);
        PdfSignatureAppearance appearance = signer.getSignatureAppearance();
        appearance
                .setReason(reason)
                .setLocation(location)

                // Specify if the appearance before field is signed will be used
                // as a background for the signed field. The "false" value is the default value.
                .setReuseAppearance(false)
                .setPageRect(rect)
                .setPageNumber(1);
        signer.setFieldName("sig");

        // Creating the signature
        IExternalSignature pks = new PrivateKeySignature(pk, digestAlgorithm, provider);
        IExternalDigest digest = new BouncyCastleDigest();

        // Sign the document using the detached mode, CMS or CAdES equivalent.
        signer.signDetached(digest, pks, chain, crlList, ocspClient, tsaClient, estimatedSize, subfilter);
    }
}
