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

import com.itextpdf.io.font.FontConstants;
import com.itextpdf.io.font.PdfEncodings;
import com.itextpdf.io.image.ImageDataFactory;
import com.itextpdf.kernel.font.PdfFontFactory;
import com.itextpdf.kernel.pdf.PdfReader;
import com.itextpdf.kernel.pdf.xobject.PdfFormXObject;
import com.itextpdf.layout.Canvas;
import com.itextpdf.layout.property.BaseDirection;
import com.itextpdf.layout.element.Paragraph;
import com.itextpdf.layout.element.Text;
import com.itextpdf.layout.property.TextAlignment;
import com.itextpdf.licensekey.LicenseKey;
import com.itextpdf.samples.SignatureTest;
import com.itextpdf.signatures.*;
import com.itextpdf.test.annotations.type.SampleTest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Test;
import org.junit.experimental.categories.Category;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;

import static org.junit.Assert.fail;

@Category(SampleTest.class)
public class C2_06_SignatureAppearance extends SignatureTest {
    public static final String KEYSTORE = "./src/test/resources/encryption/ks";
    public static final char[] PASSWORD = "password".toCharArray();
    public static final String SRC = "./src/test/resources/pdfs/hello_to_sign.pdf";
    public static final String DEST = "./target/test/resources/signatures/chapter02/signature_appearance%s.pdf";
    public static final String IMG = "./src/test/resources/img/1t3xt.gif";

    public void sign1(String src, String name, String dest,
                      Certificate[] chain, PrivateKey pk,
                      String digestAlgorithm, String provider, PdfSigner.CryptoStandard subfilter,
                      String reason, String location)
            throws GeneralSecurityException, IOException {
        // Creating the reader and the signer
        PdfReader reader = new PdfReader(src);
        PdfSigner signer = new PdfSigner(reader, new FileOutputStream(dest), false);
        // Creating the appearance
        PdfSignatureAppearance appearance = signer.getSignatureAppearance();
        appearance.setReason(reason);
        appearance.setLocation(location);
        appearance.setReuseAppearance(false);
        signer.setFieldName(name);
        // Custom text and custom font
        appearance.setLayer2Text("This document was signed by Bruno Specimen");
        appearance.setLayer2Font(PdfFontFactory.createFont(FontConstants.TIMES_ROMAN));
        // Creating the signature
        IExternalSignature pks = new PrivateKeySignature(pk, digestAlgorithm, provider);
        IExternalDigest digest = new BouncyCastleDigest();
        signer.signDetached(digest, pks, chain, null, null, null, 0, subfilter);
    }

    public void sign2(String src, String name, String dest,
                      Certificate[] chain, PrivateKey pk,
                      String digestAlgorithm, String provider, PdfSigner.CryptoStandard subfilter,
                      String reason, String location)
            throws GeneralSecurityException, IOException {
        // Creating the reader and the signer
        PdfReader reader = new PdfReader(src);
        PdfSigner signer = new PdfSigner(reader, new FileOutputStream(dest), false);
        // Creating the appearance
        PdfSignatureAppearance appearance = signer.getSignatureAppearance();
        appearance.setReason(reason);
        appearance.setLocation(location);
        appearance.setReuseAppearance(false);
        signer.setFieldName(name);
        // Creating the appearance for layer 2
        PdfFormXObject n2 = appearance.getLayer2();
        // Custom text, custom font, and right-to-left writing
        Text text = new Text("\u0644\u0648\u0631\u0627\u0646\u0633 \u0627\u0644\u0639\u0631\u0628");
        text.setFont(PdfFontFactory.createFont(/*"C:/windows/fonts/arialuni.ttf"*/
                "./src/test/resources/font/NotoNaskhArabic-Regular.ttf", PdfEncodings.IDENTITY_H, true));
        text.setBaseDirection(BaseDirection.RIGHT_TO_LEFT);
        new Canvas(n2, signer.getDocument()).add(new Paragraph(text).setTextAlignment(TextAlignment.RIGHT));
        // Creating the signature
        PrivateKeySignature pks = new PrivateKeySignature(pk, digestAlgorithm, provider);
        IExternalDigest digest = new BouncyCastleDigest();
        signer.signDetached(digest, pks, chain, null, null, null, 0, subfilter);
    }

    public void sign3(String src, String name, String dest,
                      Certificate[] chain, PrivateKey pk,
                      String digestAlgorithm, String provider, PdfSigner.CryptoStandard subfilter,
                      String reason, String location)
            throws GeneralSecurityException, IOException {
        // Creating the reader and the signer
        PdfReader reader = new PdfReader(src);
        PdfSigner signer = new PdfSigner(reader, new FileOutputStream(dest), false);
        // Creating the appearance
        PdfSignatureAppearance appearance = signer.getSignatureAppearance();
        appearance.setReason(reason);
        appearance.setLocation(location);
        appearance.setReuseAppearance(false);
        signer.setFieldName(name);
        // Custom text and background image
        appearance.setLayer2Text("This document was signed by Bruno Specimen");
        appearance.setImage(ImageDataFactory.create(IMG));
        appearance.setImageScale(1);
        // Creating the signature
        PrivateKeySignature pks = new PrivateKeySignature(pk, digestAlgorithm, provider);
        IExternalDigest digest = new BouncyCastleDigest();
        signer.signDetached(digest, pks, chain, null, null, null, 0, subfilter);
    }

    public void sign4(String src, String name, String dest,
                      Certificate[] chain, PrivateKey pk,
                      String digestAlgorithm, String provider, PdfSigner.CryptoStandard subfilter,
                      String reason, String location)
            throws GeneralSecurityException, IOException {
        // Creating the reader and the signer
        PdfReader reader = new PdfReader(src);
        PdfSigner signer = new PdfSigner(reader, new FileOutputStream(dest), false);
        // Creating the appearance
        PdfSignatureAppearance appearance = signer.getSignatureAppearance();
        appearance.setReason(reason);
        appearance.setLocation(location);
        appearance.setReuseAppearance(false);
        signer.setFieldName(name);
        // Default text and scaled background image
        appearance.setImage(ImageDataFactory.create(IMG));
        appearance.setImageScale(-1);
        // Creating the signature
        PrivateKeySignature pks = new PrivateKeySignature(pk, digestAlgorithm, provider);
        IExternalDigest digest = new BouncyCastleDigest();
        signer.signDetached(digest, pks, chain, null, null, null, 0, subfilter);
    }

    public static void main(String[] args) throws IOException, GeneralSecurityException {
        BouncyCastleProvider provider = new BouncyCastleProvider();
        Security.addProvider(provider);
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        ks.load(new FileInputStream(KEYSTORE), PASSWORD);
        String alias = ks.aliases().nextElement();
        PrivateKey pk = (PrivateKey) ks.getKey(alias, PASSWORD);
        Certificate[] chain = ks.getCertificateChain(alias);
        C2_06_SignatureAppearance app = new C2_06_SignatureAppearance();
        app.sign1(SRC, "Signature1", String.format(DEST, 1), chain, pk,
                DigestAlgorithms.SHA256, provider.getName(), PdfSigner.CryptoStandard.CMS,
                "Custom appearance example", "Ghent");
        app.sign2(SRC, "Signature1", String.format(DEST, 2), chain, pk,
                DigestAlgorithms.SHA256, provider.getName(), PdfSigner.CryptoStandard.CMS,
                "Custom appearance example", "Ghent");
        app.sign3(SRC, "Signature1", String.format(DEST, 3), chain, pk,
                DigestAlgorithms.SHA256, provider.getName(), PdfSigner.CryptoStandard.CMS,
                "Custom appearance example", "Ghent");
        app.sign4(SRC, "Signature1", String.format(DEST, 4), chain, pk,
                DigestAlgorithms.SHA256, provider.getName(), PdfSigner.CryptoStandard.CMS,
                "Custom appearance example", "Ghent");
    }

    @Test
    public void runTest() throws IOException, InterruptedException, GeneralSecurityException {
        //Load the license file to use advanced typography features
        LicenseKey.loadLicenseFile(System.getenv("ITEXT7_LICENSEKEY") + "/itextkey-typography.xml");
        new File("./target/test/resources/signatures/chapter02/").mkdirs();
        C2_06_SignatureAppearance.main(null);

        String[] resultFiles = new String[]{"signature_appearance1.pdf", "signature_appearance2.pdf",
                "signature_appearance3.pdf", "signature_appearance4.pdf"};

        String destPath = String.format(outPath, "chapter02");
        String comparePath = String.format(cmpPath, "chapter02");

        String[] errors = new String[resultFiles.length];
        boolean error = false;

        for (int i = 0; i < resultFiles.length - 1; i++) {
            String resultFile = resultFiles[i];
            String fileErrors = checkForErrors(destPath + resultFile, comparePath + "cmp_" + resultFile, destPath, null);

            if (fileErrors != null) {

                errors[i] = fileErrors;
                error = true;
            }
        }

        // Compare the last documents only in signature data
        compareSignatures(destPath + resultFiles[3], comparePath + "cmp_" + resultFiles[3]);
        if (null != getErrorMessage()) {
            errors[3] = getErrorMessage();
            error = true;
        }

        if (error) {
            fail(accumulateErrors(errors));
        }
    }
}