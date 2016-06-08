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
import com.itextpdf.kernel.geom.Rectangle;
import com.itextpdf.kernel.pdf.PdfDocument;
import com.itextpdf.kernel.pdf.PdfReader;
import com.itextpdf.kernel.pdf.PdfWriter;
import com.itextpdf.kernel.pdf.StampingProperties;
import com.itextpdf.kernel.pdf.annot.PdfAnnotation;
import com.itextpdf.layout.Document;
import com.itextpdf.layout.element.Cell;
import com.itextpdf.layout.element.Table;
import com.itextpdf.layout.renderer.CellRenderer;
import com.itextpdf.layout.renderer.DrawContext;
import com.itextpdf.samples.SignatureTest;
import com.itextpdf.signatures.*;
import com.itextpdf.test.annotations.type.SampleTest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Ignore;
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
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;

import static org.junit.Assert.fail;

@Ignore
@Category(SampleTest.class)
public class C2_11_SignatureWorkflow extends SignatureTest {
    public static final String FORM = "./target/test/resources/signatures/chapter02/form.pdf";
    public static final String ALICE = "./src/test/resources/encryption/alice";
    public static final String BOB = "./src/test/resources/encryption/bob";
    public static final String CAROL = "./src/test/resources/encryption/carol";
    public static final String DAVE = "./src/test/resources/encryption/dave";
    public static final String KEYSTORE = "./src/test/resources/encryption/ks";
    public static final char[] PASSWORD = "password".toCharArray();
    public static final String DEST = "./target/test/resources/signatures/chapter02/step%s_signed_by_%s.pdf";

    public static void main(String[] args) throws IOException, GeneralSecurityException {
        BouncyCastleProvider provider = new BouncyCastleProvider();
        Security.addProvider(provider);
        C2_11_SignatureWorkflow app = new C2_11_SignatureWorkflow();
        app.createForm();
        app.certify(ALICE, FORM, "sig1", String.format(DEST, 1, "alice"));
        app.fillOut(String.format(DEST, 1, "alice"), String.format(DEST, 2, "alice_and_filled_out_by_bob"), "approved_bob", "Read and Approved by Bob");
        app.sign(BOB, String.format(DEST, 2, "alice_and_filled_out_by_bob"), "sig2", String.format(DEST, 3, "alice_and_bob"));
        app.fillOut(String.format(DEST, 3, "alice_and_bob"), String.format(DEST, 4, "alice_and_bob_filled_out_by_carol"), "approved_carol", "Read and Approved by Carol");
        app.sign(CAROL, String.format(DEST, 4, "alice_and_bob_filled_out_by_carol"), "sig3", String.format(DEST, 5, "alice_bob_and_carol"));
        app.fillOutAndSign(DAVE, String.format(DEST, 5, "alice_bob_and_carol"), "sig4", "approved_dave", "Read and Approved by Dave", String.format(DEST, 6, "alice_bob_carol_and_dave"));
    }

    public void createForm() throws IOException {
        PdfDocument pdfDoc = new PdfDocument(new PdfWriter(FORM));
        Document doc = new Document(pdfDoc);
        Table table = new Table(1);
        table.addCell("Written by Alice");
        table.addCell(createSignatureFieldCell("sig1"));
        table.addCell("For approval by Bob");
        table.addCell(createTextFieldCell("approved_bob"));
        table.addCell(createSignatureFieldCell("sig2"));
        table.addCell("For approval by Carol");
        table.addCell(createTextFieldCell("approved_carol"));
        table.addCell(createSignatureFieldCell("sig3"));
        table.addCell("For approval by Dave");
        table.addCell(createTextFieldCell("approved_dave"));
        table.addCell(createSignatureFieldCell("sig4"));
        doc.add(table);
        doc.close();
    }

    public void certify(String keystore, String src, String name, String dest)
            throws GeneralSecurityException, IOException {
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        ks.load(new FileInputStream(keystore), PASSWORD);
        String alias = ks.aliases().nextElement();
        PrivateKey pk = (PrivateKey) ks.getKey(alias, PASSWORD);
        Certificate[] chain = ks.getCertificateChain(alias);
        /// Creating the reader and the signer
        PdfReader reader = new PdfReader(src);
        PdfSigner signer = new PdfSigner(reader, new FileOutputStream(dest), true);
        // Setting signer options
        signer.setFieldName(name);
        // TODO DEVSIX-488
        signer.setCertificationLevel(PdfSigner.CERTIFIED_FORM_FILLING);
        // Creating the signature
        IExternalSignature pks = new PrivateKeySignature(pk, "SHA-256", "BC");
        IExternalDigest digest = new BouncyCastleDigest();
        signer.signDetached(digest, pks, chain, null, null, null, 0, PdfSigner.CryptoStandard.CMS);
    }

    public void fillOut(String src, String dest, String name, String value) throws IOException {
        PdfDocument pdfDoc = new PdfDocument(new PdfReader(src), new PdfWriter(dest), new StampingProperties().useAppendMode());
        PdfAcroForm form = PdfAcroForm.getAcroForm(pdfDoc, true);
        form.getField(name).setValue(value);
        form.getField(name).setReadOnly(true);
        pdfDoc.close();
    }

    public void sign(String keystore, String src, String name, String dest)
            throws GeneralSecurityException, IOException {
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        ks.load(new FileInputStream(keystore), PASSWORD);
        String alias = ks.aliases().nextElement();
        PrivateKey pk = (PrivateKey) ks.getKey(alias, PASSWORD);
        Certificate[] chain = ks.getCertificateChain(alias);
        // Creating the reader and the signer
        PdfReader reader = new PdfReader(src);
        PdfSigner signer = new PdfSigner(reader, new FileOutputStream(dest), true);
        // Setting signer options
        signer.setFieldName(name);
        // Creating the signature
        IExternalSignature pks = new PrivateKeySignature(pk, "SHA-256", "BC");
        IExternalDigest digest = new BouncyCastleDigest();
        signer.signDetached(digest, pks, chain, null, null, null, 0, PdfSigner.CryptoStandard.CMS);
    }

    public void fillOutAndSign(String keystore, String src, String name, String fname, String value, String dest)
            throws GeneralSecurityException, IOException {
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        ks.load(new FileInputStream(keystore), PASSWORD);
        String alias = ks.aliases().nextElement();
        PrivateKey pk = (PrivateKey) ks.getKey(alias, PASSWORD);
        Certificate[] chain = ks.getCertificateChain(alias);
        // Creating the reader and the signer
        PdfReader reader = new PdfReader(src);
        PdfSigner signer = new PdfSigner(reader, new FileOutputStream(dest), true);
        PdfAcroForm form = PdfAcroForm.getAcroForm(signer.getDocument(), true);
        form.getField(fname).setValue(value);
        form.getField(fname).setReadOnly(true);
        // Setting signer options
        signer.setFieldName(name);
        // Creating the signature
        IExternalSignature pks = new PrivateKeySignature(pk, "SHA-256", "BC");
        IExternalDigest digest = new BouncyCastleDigest();
        signer.signDetached(digest, pks, chain, null, null, null, 0, PdfSigner.CryptoStandard.CMS);
    }

    protected Cell createTextFieldCell(String name) {
        Cell cell = new Cell();
        cell.setHeight(20);
        cell.setNextRenderer(new TextFieldCellRenderer(cell, name));
        return cell;
    }

    protected Cell createSignatureFieldCell(String name) {
        Cell cell = new Cell();
        cell.setHeight(50);
        cell.setNextRenderer(new SignatureFieldCellRenderer(cell, name));
        return cell;
    }


    class TextFieldCellRenderer extends CellRenderer {
        public String name;

        public TextFieldCellRenderer(Cell modelElement, String name) {
            super(modelElement);
            this.name = name;
        }

        @Override
        public void draw(DrawContext drawContext) {
            super.draw(drawContext);
            PdfFormField field = PdfFormField.createText(drawContext.getDocument(), getOccupiedAreaBBox(), name);
            PdfAcroForm.getAcroForm(drawContext.getDocument(), true).addField(field);
        }
    }


    class SignatureFieldCellRenderer extends CellRenderer {
        public String name;

        public SignatureFieldCellRenderer(Cell modelElement, String name) {
            super(modelElement);
            this.name = name;
        }

        @Override
        public void draw(DrawContext drawContext) {
            super.draw(drawContext);
            PdfFormField field = PdfFormField.createSignature(drawContext.getDocument(), getOccupiedAreaBBox());
            field.setFieldName(name);
            field.getWidgets().get(0).setHighlightMode(PdfAnnotation.HIGHLIGHT_INVERT);
            field.getWidgets().get(0).setFlags(PdfAnnotation.PRINT);
            PdfAcroForm.getAcroForm(drawContext.getDocument(), true).addField(field);
        }
    }


    @Test
    public void runTest() throws IOException, InterruptedException, GeneralSecurityException {
        new File("./target/test/resources/signatures/chapter02/").mkdirs();
        C2_11_SignatureWorkflow.main(null);

        String[] resultFiles = new String[]{"step1_signed_by_alice.pdf", "step2_signed_by_alice_and_filled_out_by_bob.pdf", "step3_signed_by_alice_and_bob.pdf",
                "step4_signed_by_alice_and_bob_filled_out_by_carol.pdf", "step5_signed_by_alice_bob_and_carol.pdf", "step6_signed_by_alice_bob_carol_and_dave.pdf"};


        String destPath = String.format(outPath, "chapter02");
        String comparePath = String.format(cmpPath, "chapter02");

        String[] errors = new String[resultFiles.length];
        boolean error = false;

        HashMap<Integer, List<Rectangle>> ignoredAreas = new HashMap<Integer, List<Rectangle>>() {
            {
                put(1, Arrays.asList(new Rectangle(38f, 743f, 215f, 759f), new Rectangle(38f, 676f, 215f, 692f), new Rectangle(38f, 611f, 215f, 627f)));
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
