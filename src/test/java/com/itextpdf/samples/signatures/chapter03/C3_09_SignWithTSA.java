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

import com.itextpdf.kernel.geom.Rectangle;
import com.itextpdf.kernel.pdf.PdfReader;
import com.itextpdf.kernel.pdf.StampingProperties;
import com.itextpdf.signatures.BouncyCastleDigest;
import com.itextpdf.signatures.DigestAlgorithms;
import com.itextpdf.signatures.ICrlClient;
import com.itextpdf.signatures.IExternalDigest;
import com.itextpdf.signatures.IExternalSignature;
import com.itextpdf.signatures.IOcspClient;
import com.itextpdf.signatures.OcspClientBouncyCastle;
import com.itextpdf.signatures.PdfSignatureAppearance;
import com.itextpdf.signatures.PdfSigner;
import com.itextpdf.signatures.ITSAClient;
import com.itextpdf.signatures.PrivateKeySignature;
import com.itextpdf.signatures.TSAClientBouncyCastle;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.util.Collection;
import java.util.Properties;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class C3_09_SignWithTSA {
    public static final String DEST = "./target/test/resources/signatures/chapter03/";

    public static final String SRC = "./src/test/resources/pdfs/hello.pdf";

    public static final String[] RESULT_FILES = new String[] {
            "hello_cacert_ocsp_ts.pdf"
    };

    public static void main(String[] args) throws IOException, GeneralSecurityException {
        File file = new File(DEST);
        file.mkdirs();

        Properties properties = new Properties();

        // Specify the correct path to the certificate
        properties.load(new FileInputStream("c:/home/blowagie/key.properties"));
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

        /* Create an instance of TSAClientBouncyCastle, an implementation of TSAClient.
         * Pass the timestamp authority server url.
         * Note that not all TSA would require user credentials.
         */
        ITSAClient tsaClient = new TSAClientBouncyCastle(tsaUrl, tsaUser, tsaPass);

        new C3_09_SignWithTSA().sign(SRC, DEST + RESULT_FILES[0], chain, pk,
                DigestAlgorithms.SHA256, provider.getName(), PdfSigner.CryptoStandard.CMS,
                "Test", "Ghent", null, ocspClient, tsaClient, 0);
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
        // Pass the created TSAClient to the signing method.
        signer.signDetached(digest, pks, chain, crlList, ocspClient, tsaClient, estimatedSize, subfilter);
    }
}
