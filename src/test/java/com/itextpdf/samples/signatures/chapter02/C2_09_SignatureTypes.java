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
import com.itextpdf.kernel.pdf.PdfDocument;
import com.itextpdf.kernel.pdf.PdfName;
import com.itextpdf.kernel.pdf.PdfReader;
import com.itextpdf.kernel.pdf.PdfString;
import com.itextpdf.kernel.pdf.PdfWriter;
import com.itextpdf.kernel.pdf.StampingProperties;
import com.itextpdf.kernel.pdf.annot.PdfAnnotation;
import com.itextpdf.kernel.pdf.annot.PdfTextAnnotation;
import com.itextpdf.kernel.pdf.canvas.PdfCanvas;
import com.itextpdf.layout.Canvas;
import com.itextpdf.layout.property.TextAlignment;
import com.itextpdf.samples.SignatureTest;
import com.itextpdf.signatures.BouncyCastleDigest;
import com.itextpdf.signatures.DigestAlgorithms;
import com.itextpdf.signatures.IExternalDigest;
import com.itextpdf.signatures.PdfSignatureAppearance;
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
import org.junit.Ignore;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import static org.junit.Assert.fail;

@Ignore
@Category(SampleTest.class)
public class C2_09_SignatureTypes extends SignatureTest {
    public static final String KEYSTORE = "./src/test/resources/encryption/ks";
    public static final char[] PASSWORD = "password".toCharArray();
    public static final String SRC = "./src/test/resources/pdfs/hello.pdf";
    public static final String DEST = "./target/test/resources/signatures/chapter02/hello_level_%s.pdf";

    public void sign(String src, String dest,
                     Certificate[] chain, PrivateKey pk,
                     String digestAlgorithm, String provider,
                     PdfSigner.CryptoStandard subfilter, int certificationLevel,
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
        Rectangle rect = new Rectangle(36, 648, 200, 100);
        appearance
                .setPageRect(rect)
                .setPageNumber(1);
        signer.setFieldName("sig");
        signer.setCertificationLevel(certificationLevel);
        // Creating the signature
        PrivateKeySignature pks = new PrivateKeySignature(pk, digestAlgorithm, provider);
        IExternalDigest digest = new BouncyCastleDigest();
        signer.signDetached(digest, pks, chain, null, null, null, 0, subfilter);
    }

    public void addText(String src, String dest) throws IOException {
        PdfReader reader = new PdfReader(src);
        PdfDocument pdfDoc = new PdfDocument(reader, new PdfWriter(dest), new StampingProperties().useAppendMode());
        new Canvas(new PdfCanvas(pdfDoc.getFirstPage()), pdfDoc, pdfDoc.getFirstPage().getPageSize())
                .showTextAligned("TOP SECRET", 36, 820, TextAlignment.LEFT);
        pdfDoc.close();
    }

    public void addAnnotation(String src, String dest) throws IOException {
        PdfReader reader = new PdfReader(src);
        PdfDocument pdfDoc = new PdfDocument(reader, new PdfWriter(dest), new StampingProperties().useAppendMode());
        PdfAnnotation comment = new PdfTextAnnotation(new Rectangle(200, 800, 50, 20))
                .setIconName(new PdfName("Comment"))
                .setTitle(new PdfString("Finally Signed!"))
                .setContents("Bruno Specimen has finally signed the document")
                .setOpen(true);
        pdfDoc.getFirstPage().addAnnotation(comment);
        pdfDoc.close();
    }

    public void addWrongAnnotation(String src, String dest) throws IOException {
        PdfReader reader = new PdfReader(src);
        PdfDocument pdfDoc = new PdfDocument(reader, new PdfWriter(dest));
        PdfAnnotation comment = new PdfTextAnnotation(new Rectangle(200, 800, 50, 20))
                .setIconName(new PdfName("Comment"))
                .setTitle(new PdfString("Finally Signed!"))
                .setContents("Bruno Specimen has finally signed the document")
                .setOpen(true);
        pdfDoc.getFirstPage().addAnnotation(comment);
        pdfDoc.close();
    }

    public void signAgain(String src, String dest, Certificate[] chain, PrivateKey pk,
                          String digestAlgorithm, String provider,
                          PdfSigner.CryptoStandard subfilter,
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
        Rectangle rect = new Rectangle(36, 700, 200, 100);
        appearance
                .setPageRect(rect)
                .setPageNumber(1);
        signer.setFieldName("Signature2");
        // Creating the signature
        PrivateKeySignature pks = new PrivateKeySignature(pk, digestAlgorithm, provider);
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
        C2_09_SignatureTypes app = new C2_09_SignatureTypes();
        // TODO DEVSIX-488
        app.sign(SRC, String.format(DEST, 1), chain, pk, DigestAlgorithms.SHA256, provider.getName(), PdfSigner.CryptoStandard.CMS, PdfSigner.NOT_CERTIFIED, "Test 1", "Ghent");
        app.sign(SRC, String.format(DEST, 2), chain, pk, DigestAlgorithms.SHA256, provider.getName(), PdfSigner.CryptoStandard.CMS, PdfSigner.CERTIFIED_FORM_FILLING_AND_ANNOTATIONS, "Test 1", "Ghent");
        app.sign(SRC, String.format(DEST, 3), chain, pk, DigestAlgorithms.SHA256, provider.getName(), PdfSigner.CryptoStandard.CMS, PdfSigner.CERTIFIED_FORM_FILLING, "Test 1", "Ghent");
        app.sign(SRC, String.format(DEST, 4), chain, pk, DigestAlgorithms.SHA256, provider.getName(), PdfSigner.CryptoStandard.CMS, PdfSigner.CERTIFIED_NO_CHANGES_ALLOWED, "Test 1", "Ghent");
        app.addAnnotation(String.format(DEST, 1), String.format(DEST, "1_annotated"));
        app.addAnnotation(String.format(DEST, 2), String.format(DEST, "2_annotated"));
        app.addAnnotation(String.format(DEST, 3), String.format(DEST, "3_annotated"));
        app.addAnnotation(String.format(DEST, 4), String.format(DEST, "4_annotated"));
        app.addWrongAnnotation(String.format(DEST, 1), String.format(DEST, "1_annotated_wrong"));
        app.addWrongAnnotation(SRC, String.format(DEST, "1_annotated_wrong"));
        app.addText(String.format(DEST, 1), String.format(DEST, "1_text"));
        app.signAgain(String.format(DEST, 1), String.format(DEST, "1_double"), chain, pk, DigestAlgorithms.SHA256, provider.getName(), PdfSigner.CryptoStandard.CMS, "Second signature test", "Gent");
        app.signAgain(String.format(DEST, 2), String.format(DEST, "2_double"), chain, pk, DigestAlgorithms.SHA256, provider.getName(), PdfSigner.CryptoStandard.CMS, "Second signature test", "Gent");
        app.signAgain(String.format(DEST, 3), String.format(DEST, "3_double"), chain, pk, DigestAlgorithms.SHA256, provider.getName(), PdfSigner.CryptoStandard.CMS, "Second signature test", "Gent");
        app.signAgain(String.format(DEST, 4), String.format(DEST, "4_double"), chain, pk, DigestAlgorithms.SHA256, provider.getName(), PdfSigner.CryptoStandard.CMS, "Second signature test", "Gent");
    }

    @Test
    public void runTest() throws IOException, InterruptedException, GeneralSecurityException {
        new File("./target/test/resources/signatures/chapter02/").mkdirs();
        C2_09_SignatureTypes.main(null);

        String[] resultFiles =
                new String[]{"hello_level_1.pdf", "hello_level_2.pdf", "hello_level_3.pdf", "hello_level_4.pdf",
                        "hello_level_2_annotated.pdf", "hello_level_3_annotated.pdf", "hello_level_4_annotated.pdf",
                        "hello_level_1_text.pdf", // this document's signature is not broken, that's why verifier doesn't show any errors;
                        // this document is invalid from certificate point of view, which is not checked by itext
                        "hello_level_1_double.pdf", "hello_level_2_double.pdf", "hello_level_3_double.pdf", "hello_level_4_double.pdf"};

        String destPath = String.format(outPath, "chapter02");
        String comparePath = String.format(cmpPath, "chapter02");

        String[] errors = new String[resultFiles.length];
        boolean error = false;
        int indexOfInvalidFile = 4;

        HashMap<Integer, List<Rectangle>> ignoredAreas = new HashMap<Integer, List<Rectangle>>() {
            {
                put(1, Arrays.asList(new Rectangle(38f, 758f, 110f, 763f), new Rectangle(38f, 710f, 110f, 715f)));
            }
        };

        for (int i = 0; i < resultFiles.length; i++) {
            String resultFile = resultFiles[i];
            String fileErrors = checkForErrors(destPath + resultFile, comparePath + "cmp_" + resultFile, destPath, ignoredAreas);

            if (i == indexOfInvalidFile) {
                if (fileErrors == null) {
                    errors[i] = "Document signature was expected to be invalid.";
                    error = true;
                }
            } else if (fileErrors != null) {
                errors[i] = fileErrors;
                error = true;
            }
        }

        if (error) {
            fail(accumulateErrors(errors));
        }
    }
}
