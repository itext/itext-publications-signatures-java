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
package com.itextpdf.samples.signatures.chapter02;

import com.itextpdf.kernel.geom.Rectangle;
import com.itextpdf.kernel.pdf.PdfReader;
import com.itextpdf.samples.SignatureTest;
import com.itextpdf.signatures.BouncyCastleDigest;
import com.itextpdf.signatures.DigestAlgorithms;
import com.itextpdf.signatures.IExternalDigest;
import com.itextpdf.signatures.IExternalSignature;
import com.itextpdf.signatures.PdfSigner;
import com.itextpdf.signatures.PrivateKeySignature;
import com.itextpdf.test.annotations.type.SampleTest;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import static org.junit.Assert.fail;

@Category(SampleTest.class)
public class C2_03_SignEmptyField extends SignatureTest {
    public static final String KEYSTORE = "./src/test/resources/encryption/ks";
    public static final char[] PASSWORD = "password".toCharArray();
    public static final String SRC = "./src/test/resources/pdfs/hello_to_sign.pdf";
    public static final String DEST = "./target/test/resources/signatures/chapter02/field_signed%s.pdf";

    public void sign(String src, String name, String dest,
                     Certificate[] chain,
                     PrivateKey pk, String digestAlgorithm, String provider,
                     PdfSigner.CryptoStandard subfilter,
                     String reason, String location)
            throws GeneralSecurityException, IOException {
        // Creating the reader and the signer
        PdfReader reader = new PdfReader(src);
        PdfSigner signer = new PdfSigner(reader, new FileOutputStream(dest), false);
        // Creating the appearance
        signer.getSignatureAppearance()
                .setReason(reason)
                .setLocation(location)
                .setReuseAppearance(false);
        signer.setFieldName(name);
        // Creating the signature
        IExternalSignature pks = new PrivateKeySignature(pk, digestAlgorithm, provider);
        IExternalDigest digest = new BouncyCastleDigest();
        signer.signDetached(digest, pks, chain, null, null, null, 0, subfilter);
    }

    public static void main(String[] args) throws GeneralSecurityException, IOException {
        BouncyCastleProvider provider = new BouncyCastleProvider();
        Security.addProvider(provider);
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        ks.load(new FileInputStream(KEYSTORE), PASSWORD);
        String alias = ks.aliases().nextElement();
        PrivateKey pk = (PrivateKey) ks.getKey(alias, PASSWORD);
        Certificate[] chain = ks.getCertificateChain(alias);
        C2_03_SignEmptyField app = new C2_03_SignEmptyField();
        app.sign(SRC, "Signature1", String.format(DEST, 1), chain, pk, DigestAlgorithms.SHA256, provider.getName(), PdfSigner.CryptoStandard.CMS, "Test 1", "Ghent");
        app.sign(SRC, "Signature1", String.format(DEST, 2), chain, pk, DigestAlgorithms.SHA512, provider.getName(), PdfSigner.CryptoStandard.CMS, "Test 2", "Ghent");
        app.sign(SRC, "Signature1", String.format(DEST, 3), chain, pk, DigestAlgorithms.SHA256, provider.getName(), PdfSigner.CryptoStandard.CADES, "Test 3", "Ghent");
        app.sign(SRC, "Signature1", String.format(DEST, 4), chain, pk, DigestAlgorithms.RIPEMD160, provider.getName(), PdfSigner.CryptoStandard.CADES, "Test 4", "Ghent");
    }

    @Test
    public void runTest() throws IOException, InterruptedException, GeneralSecurityException {
        new File("./target/test/resources/signatures/chapter02/").mkdirs();
        C2_03_SignEmptyField.main(null);

        String[] resultFiles =
                new String[]{"field_signed1.pdf", "field_signed2.pdf", "field_signed3.pdf", "field_signed4.pdf"};

        String destPath = String.format(outPath, "chapter02");
        String comparePath = String.format(cmpPath, "chapter02");

        String[] errors = new String[resultFiles.length];
        boolean error = false;

        HashMap<Integer, List<Rectangle>> ignoredAreas = new HashMap<Integer, List<Rectangle>>() {
            {
                put(1, Arrays.asList(new Rectangle(46, 472, 287, 255)));
            }
        };

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
