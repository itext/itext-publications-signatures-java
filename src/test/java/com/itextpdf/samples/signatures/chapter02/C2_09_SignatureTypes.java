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
package com.itextpdf.samples.signatures.chapter02;

import com.itextpdf.kernel.geom.Rectangle;
import com.itextpdf.kernel.pdf.PdfReader;
import com.itextpdf.kernel.pdf.PdfDocument;
import com.itextpdf.kernel.pdf.PdfWriter;
import com.itextpdf.kernel.pdf.PdfPage;
import com.itextpdf.kernel.pdf.PdfString;
import com.itextpdf.kernel.pdf.PdfName;
import com.itextpdf.kernel.pdf.StampingProperties;
import com.itextpdf.kernel.pdf.annot.PdfAnnotation;
import com.itextpdf.kernel.pdf.annot.PdfTextAnnotation;
import com.itextpdf.layout.Canvas;
import com.itextpdf.layout.property.TextAlignment;
import com.itextpdf.signatures.BouncyCastleDigest;
import com.itextpdf.signatures.DigestAlgorithms;
import com.itextpdf.signatures.IExternalDigest;
import com.itextpdf.signatures.PdfSignatureAppearance;
import com.itextpdf.signatures.PdfSigner;
import com.itextpdf.signatures.PrivateKeySignature;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class C2_09_SignatureTypes {
    public static final String DEST = "./target/signatures/chapter02/";
    public static final String KEYSTORE = "./src/test/resources/encryption/ks";
    public static final String SRC = "./src/test/resources/pdfs/hello.pdf";

    public static final char[] PASSWORD = "password".toCharArray();

    public static final String[] RESULT_FILES = new String[] {
            "hello_level_1.pdf", "hello_level_2.pdf",
            "hello_level_3.pdf", "hello_level_4.pdf",
            "hello_level_1_annotated.pdf", "hello_level_2_annotated.pdf",
            "hello_level_3_annotated.pdf", "hello_level_4_annotated.pdf",
            "hello_level_1_annotated_wrong.pdf", "hello_level_1_text.pdf",
            "hello_level_1_double.pdf", "hello_level_2_double.pdf",
            "hello_level_3_double.pdf", "hello_level_4_double.pdf",
    };

    public void sign(String src, String dest, Certificate[] chain, PrivateKey pk, String digestAlgorithm,
            String provider, PdfSigner.CryptoStandard subfilter, int certificationLevel,
            String reason, String location)
            throws GeneralSecurityException, IOException {
        PdfReader reader = new PdfReader(src);
        PdfSigner signer = new PdfSigner(reader, new FileOutputStream(dest), new StampingProperties());

        // Create the signature appearance
        PdfSignatureAppearance appearance = signer.getSignatureAppearance();
        appearance.setReason(reason);
        appearance.setLocation(location);

        Rectangle rect = new Rectangle(36, 648, 200, 100);
        appearance.setPageRect(rect);
        appearance.setPageNumber(1);
        signer.setFieldName("sig");

        /* Set the document's certification level. This parameter defines if changes are allowed
         * after the applying of the signature.
         */
        signer.setCertificationLevel(certificationLevel);

        PrivateKeySignature pks = new PrivateKeySignature(pk, digestAlgorithm, provider);
        IExternalDigest digest = new BouncyCastleDigest();

        // Sign the document using the detached mode, CMS or CAdES equivalent.
        signer.signDetached(digest, pks, chain, null, null, null, 0, subfilter);
    }

    public void addText(String src, String dest) throws IOException {
        PdfReader reader = new PdfReader(src);
        PdfDocument pdfDoc = new PdfDocument(reader, new PdfWriter(dest), new StampingProperties().useAppendMode());
        PdfPage firstPage = pdfDoc.getFirstPage();

        new Canvas(firstPage, firstPage.getPageSize()).showTextAligned("TOP SECRET", 36, 820,
                TextAlignment.LEFT);

        pdfDoc.close();
    }

    public void addAnnotation(String src, String dest) throws IOException {
        PdfReader reader = new PdfReader(src);
        PdfDocument pdfDoc = new PdfDocument(reader, new PdfWriter(dest), new StampingProperties().useAppendMode());

        PdfAnnotation comment = new PdfTextAnnotation(new Rectangle(200, 800, 50, 20))
                .setOpen(true)
                .setIconName(new PdfName("Comment"))
                .setTitle(new PdfString("Finally Signed!"))
                .setContents("Bruno Specimen has finally signed the document");
        pdfDoc.getFirstPage().addAnnotation(comment);

        pdfDoc.close();
    }

    public void addWrongAnnotation(String src, String dest) throws IOException {
        PdfReader reader = new PdfReader(src);
        PdfDocument pdfDoc = new PdfDocument(reader, new PdfWriter(dest));

        PdfAnnotation comment = new PdfTextAnnotation(new Rectangle(200, 800, 50, 20))
                .setOpen(true)
                .setIconName(new PdfName("Comment"))
                .setTitle(new PdfString("Finally Signed!"))
                .setContents("Bruno Specimen has finally signed the document");
        pdfDoc.getFirstPage().addAnnotation(comment);

        pdfDoc.close();
    }

    public void signAgain(String src, String dest, Certificate[] chain, PrivateKey pk, String digestAlgorithm,
            String provider, PdfSigner.CryptoStandard subfilter, String reason, String location)
            throws GeneralSecurityException, IOException {
        PdfReader reader = new PdfReader(src);
        PdfSigner signer = new PdfSigner(reader, new FileOutputStream(dest), new StampingProperties().useAppendMode());

        PdfSignatureAppearance appearance = signer.getSignatureAppearance();
        appearance.setReason(reason);
        appearance.setLocation(location);
        appearance.setReuseAppearance(false);
        Rectangle rect = new Rectangle(36, 700, 200, 100);
        appearance.setPageRect(rect);
        appearance.setPageNumber(1);
        signer.setFieldName("Signature2");

        PrivateKeySignature pks = new PrivateKeySignature(pk, digestAlgorithm, provider);
        IExternalDigest digest = new BouncyCastleDigest();
        signer.signDetached(digest, pks, chain, null, null, null, 0, subfilter);

    }

    public static void main(String[] args) throws GeneralSecurityException, IOException {
        File file = new File(DEST);
        file.mkdirs();

        BouncyCastleProvider provider = new BouncyCastleProvider();
        Security.addProvider(provider);
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        ks.load(new FileInputStream(KEYSTORE), PASSWORD);
        String alias = ks.aliases().nextElement();
        PrivateKey pk = (PrivateKey) ks.getKey(alias, PASSWORD);
        Certificate[] chain = ks.getCertificateChain(alias);

        C2_09_SignatureTypes app = new C2_09_SignatureTypes();
        app.sign(SRC, DEST + RESULT_FILES[0], chain, pk, DigestAlgorithms.SHA256, provider.getName(),
                PdfSigner.CryptoStandard.CMS, PdfSigner.NOT_CERTIFIED,
                "Test 1", "Ghent");
        app.sign(SRC, DEST + RESULT_FILES[1], chain, pk, DigestAlgorithms.SHA256, provider.getName(),
                PdfSigner.CryptoStandard.CMS, PdfSigner.CERTIFIED_FORM_FILLING_AND_ANNOTATIONS,
                "Test 1", "Ghent");
        app.sign(SRC, DEST + RESULT_FILES[2], chain, pk, DigestAlgorithms.SHA256, provider.getName(),
                PdfSigner.CryptoStandard.CMS, PdfSigner.CERTIFIED_FORM_FILLING,
                "Test 1", "Ghent");
        app.sign(SRC, DEST + RESULT_FILES[3], chain, pk, DigestAlgorithms.SHA256, provider.getName(),
                PdfSigner.CryptoStandard.CMS, PdfSigner.CERTIFIED_NO_CHANGES_ALLOWED,
                "Test 1", "Ghent");

        app.addAnnotation(DEST + RESULT_FILES[0], DEST + RESULT_FILES[4]);
        app.addAnnotation(DEST + RESULT_FILES[1], DEST + RESULT_FILES[5]);
        app.addAnnotation(DEST + RESULT_FILES[2], DEST + RESULT_FILES[6]);
        app.addAnnotation(DEST + RESULT_FILES[3], DEST + RESULT_FILES[7]);

        app.addWrongAnnotation(DEST + RESULT_FILES[0], DEST + RESULT_FILES[8]);
        app.addText(DEST + RESULT_FILES[0], DEST + RESULT_FILES[9]);

        app.signAgain(DEST + RESULT_FILES[0], DEST + RESULT_FILES[10], chain, pk,
                DigestAlgorithms.SHA256, provider.getName(),
                PdfSigner.CryptoStandard.CMS, "Second signature test", "Gent");
        app.signAgain(DEST + RESULT_FILES[1], DEST + RESULT_FILES[11], chain, pk,
                DigestAlgorithms.SHA256, provider.getName(),
                PdfSigner.CryptoStandard.CMS, "Second signature test", "Gent");
        app.signAgain(DEST + RESULT_FILES[2], DEST + RESULT_FILES[12], chain, pk,
                DigestAlgorithms.SHA256, provider.getName(),
                PdfSigner.CryptoStandard.CMS, "Second signature test", "Gent");
        app.signAgain(DEST + RESULT_FILES[3], DEST + RESULT_FILES[13], chain, pk,
                DigestAlgorithms.SHA256, provider.getName(),
                PdfSigner.CryptoStandard.CMS, "Second signature test", "Gent");
    }
}
