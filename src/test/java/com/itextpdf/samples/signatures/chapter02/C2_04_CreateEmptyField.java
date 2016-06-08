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

import com.itextpdf.forms.PdfAcroForm;
import com.itextpdf.forms.fields.PdfFormField;
import com.itextpdf.forms.fields.PdfSignatureFormField;
import com.itextpdf.kernel.color.Color;
import com.itextpdf.kernel.geom.Rectangle;
import com.itextpdf.kernel.pdf.*;
import com.itextpdf.kernel.pdf.annot.PdfAnnotation;
import com.itextpdf.kernel.pdf.canvas.PdfCanvas;
import com.itextpdf.kernel.pdf.xobject.PdfFormXObject;
import com.itextpdf.layout.Canvas;
import com.itextpdf.layout.Document;
import com.itextpdf.layout.element.Paragraph;
import com.itextpdf.layout.property.TextAlignment;
import com.itextpdf.samples.SignatureTest;
import com.itextpdf.signatures.DigestAlgorithms;
import com.itextpdf.signatures.PdfSigner;
import com.itextpdf.test.annotations.type.SampleTest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
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

import static org.junit.Assert.fail;

@Category(SampleTest.class)
public class C2_04_CreateEmptyField extends SignatureTest {
    public static final String KEYSTORE = "./src/test/resources/encryption/ks";
    public static final char[] PASSWORD = "password".toCharArray();
    public static final String SRC = "./src/test/resources/pdfs/hello.pdf";
    public static final String DEST = "./target/test/resources/signatures/chapter02/field_signed.pdf";
    public static final String UNSIGNED = "./target/test/resources/signatures/chapter02/hello_empty.pdf";
    public static final String SIGNAME = "Signature1";
    public static final String UNSIGNED2 = "./target/test/resources/signatures/chapter02/hello_empty2.pdf";

    public void createPdf(String filename) throws IOException {
        PdfDocument pdfDoc = new PdfDocument(new PdfWriter(filename));
        Document doc = new Document(pdfDoc);
        doc.add(new Paragraph("Hello World!"));
        // create a signature form field
        PdfFormField field = PdfFormField.createSignature(pdfDoc, new Rectangle(72, 632, 200, 100));
        field.setFieldName(SIGNAME);
        // set the widget properties
        field.setPage(1);
        field.getWidgets().get(0).setHighlightMode(PdfAnnotation.HIGHLIGHT_INVERT).setFlags(PdfAnnotation.PRINT);

        PdfDictionary mkDictionary = field.getWidgets().get(0).getAppearanceCharacteristics();
        if (null == mkDictionary) {
            mkDictionary = new PdfDictionary();
        }
        PdfArray black = new PdfArray();
        black.add(new PdfNumber(Color.BLACK.getColorValue()[0]));
        black.add(new PdfNumber(Color.BLACK.getColorValue()[1]));
        black.add(new PdfNumber(Color.BLACK.getColorValue()[2]));
        mkDictionary.put(PdfName.BC, black);

        PdfArray white = new PdfArray();
        black.add(new PdfNumber(Color.WHITE.getColorValue()[0]));
        black.add(new PdfNumber(Color.WHITE.getColorValue()[1]));
        black.add(new PdfNumber(Color.WHITE.getColorValue()[2]));
        mkDictionary.put(PdfName.BG, white);

        field.getWidgets().get(0).setAppearanceCharacteristics(mkDictionary);

        // add the field
        PdfAcroForm.getAcroForm(pdfDoc, true).addField(field);
        // maybe you want to define an appearance
        Rectangle rect = new Rectangle(0, 0, 200, 100);
        PdfFormXObject xObject = new PdfFormXObject(rect);
        PdfCanvas canvas = new PdfCanvas(xObject, pdfDoc);
        canvas
                .setStrokeColor(Color.BLUE)
                .setFillColor(Color.LIGHT_GRAY)
                .rectangle(0.5f, 0.5f, 199.5f, 99.5f)
                .fillStroke()
                .setFillColor(Color.BLUE);
        new Canvas(canvas, pdfDoc, rect).showTextAligned("SIGN HERE", 100, 50,
                TextAlignment.CENTER, (float) Math.toRadians(25));
        // TODO Acrobat does not render new appearance (Foxit however does)
        field.getWidgets().get(0).setNormalAppearance(xObject.getPdfObject());
        // Close the document
        doc.close();
    }

    public void addField(String src, String dest) throws IOException {
        PdfDocument pdfDoc = new PdfDocument(new PdfReader(src), new PdfWriter(dest));
        // create a signature form field
        PdfSignatureFormField field = PdfFormField.createSignature(pdfDoc, new Rectangle(72, 632, 200, 100));
        field.setFieldName(SIGNAME);
        // set the widget properties
        field.getWidgets().get(0).setHighlightMode(PdfAnnotation.HIGHLIGHT_OUTLINE).setFlags(PdfAnnotation.PRINT);
        // add the field
        PdfAcroForm.getAcroForm(pdfDoc, true).addField(field);
        // close the document
        pdfDoc.close();
    }

    public static void main(String[] args) throws IOException, GeneralSecurityException {
        new File("./target/test/resources/signatures/chapter02/").mkdirs();
        C2_04_CreateEmptyField appCreate = new C2_04_CreateEmptyField();
        appCreate.createPdf(UNSIGNED);
        appCreate.addField(SRC, UNSIGNED2);

        BouncyCastleProvider provider = new BouncyCastleProvider();
        Security.addProvider(provider);
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        ks.load(new FileInputStream(KEYSTORE), PASSWORD);
        String alias = ks.aliases().nextElement();
        PrivateKey pk = (PrivateKey) ks.getKey(alias, PASSWORD);
        Certificate[] chain = ks.getCertificateChain(alias);
        C2_03_SignEmptyField appSign = new C2_03_SignEmptyField();
        appSign.sign(UNSIGNED, SIGNAME, DEST, chain, pk, DigestAlgorithms.SHA256,
                provider.getName(), PdfSigner.CryptoStandard.CMS, "Test", "Ghent");
    }

    @Test
    public void runTest() throws IOException, InterruptedException, GeneralSecurityException {
        C2_04_CreateEmptyField.main(null);

        String[] resultFiles =
                new String[]{"field_signed.pdf", "hello_empty.pdf", "hello_empty2.pdf"};

        String destPath = String.format(outPath, "chapter02");
        String comparePath = String.format(cmpPath, "chapter02");

        String[] errors = new String[resultFiles.length];
        boolean error = false;

        HashMap<Integer, List<Rectangle>> ignoredAreas = new HashMap<Integer, List<Rectangle>>() {
            {
                put(1, Arrays.asList(new Rectangle(72, 632, 200, 100)));
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