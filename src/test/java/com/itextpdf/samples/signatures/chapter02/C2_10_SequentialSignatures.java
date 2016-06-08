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
import com.itextpdf.kernel.pdf.PdfDocument;
import com.itextpdf.kernel.pdf.PdfReader;
import com.itextpdf.kernel.pdf.PdfWriter;
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

@Ignore
@Category(SampleTest.class)
public class C2_10_SequentialSignatures extends SignatureTest {
    public static final String FORM = "./target/test/resources/signatures/chapter02/multiple_signatures.pdf";
    public static final String ALICE = "./src/test/resources/encryption/alice";
    public static final String BOB = "./src/test/resources/encryption/bob";
    public static final String CAROL = "./src/test/resources/encryption/carol";
    public static final String KEYSTORE = "./src/test/resources/encryption/ks";
    public static final char[] PASSWORD = "password".toCharArray();
    public static final String DEST = "./target/test/resources/signatures/chapter02/signed_by_%s.pdf";

    public void createForm() throws IOException {
        PdfDocument pdfDoc = new PdfDocument(new PdfWriter(FORM));
        Document doc = new Document(pdfDoc);
        Table table = new Table(1);
        table.addCell("Signer 1: Alice");
        table.addCell(createSignatureFieldCell("sig1"));
//        table.addCell("Signer 2: Bob");
//        table.addCell(createSignatureFieldCell("sig2"));
//        table.addCell("Signer 3: Carol");
//        table.addCell(createSignatureFieldCell("sig3"));
        doc.add(table);
        doc.close();
    }

    protected Cell createSignatureFieldCell(String name) {
        Cell cell = new Cell();
        cell.setHeight(50);
        cell.setNextRenderer(new SignatureFieldCellRenderer(cell, name));
        return cell;
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


    public void sign(String keystore, int level, String src, String name, String dest)
            throws GeneralSecurityException, IOException {
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        ks.load(new FileInputStream(keystore), PASSWORD);
        String alias = ks.aliases().nextElement();
        PrivateKey pk = (PrivateKey) ks.getKey(alias, PASSWORD);
        Certificate[] chain = ks.getCertificateChain(alias);
        // Creating the reader and the signer
        PdfReader reader = new PdfReader(src);
        PdfSigner signer = new PdfSigner(reader, new FileOutputStream(dest), true);
        signer.getDocument().setFlushUnusedObjects(true);
        // Setting signer options
        signer.setFieldName(name);
        signer.setCertificationLevel(level);
        // Creating the signature
        IExternalSignature pks = new PrivateKeySignature(pk, "SHA-256", "BC");
        IExternalDigest digest = new BouncyCastleDigest();
        signer.signDetached(digest, pks, chain, null, null, null, 0, PdfSigner.CryptoStandard.CMS);
    }

    public static void main(String[] args) throws IOException, GeneralSecurityException {
        BouncyCastleProvider provider = new BouncyCastleProvider();
        Security.addProvider(provider);
        C2_10_SequentialSignatures app = new C2_10_SequentialSignatures();
        app.createForm();

        // TODO DEVSIX-488
        app.sign(ALICE, PdfSigner.CERTIFIED_FORM_FILLING, FORM, "sig1", String.format(DEST, "alice"));
//        app.sign(BOB, PdfSigner.NOT_CERTIFIED, String.format(DEST, "alice"), "sig2", String.format(DEST, "bob"));
//        app.sign(CAROL, PdfSigner.NOT_CERTIFIED, String.format(DEST, "bob"), "sig3", String.format(DEST, "carol"));
//
//        app.sign(ALICE, PdfSigner.NOT_CERTIFIED, FORM, "sig1", String.format(DEST, "alice2"));
//        app.sign(BOB, PdfSigner.NOT_CERTIFIED, String.format(DEST, "alice2"), "sig2", String.format(DEST, "bob2"));
//        app.sign(CAROL, PdfSigner.CERTIFIED_FORM_FILLING, String.format(DEST, "bob2"), "sig3", String.format(DEST, "carol2"));
//
//        app.sign(ALICE, PdfSigner.NOT_CERTIFIED, FORM, "sig1", String.format(DEST, "alice3"));
//        app.sign(BOB, PdfSigner.NOT_CERTIFIED, String.format(DEST, "alice3"), "sig2", String.format(DEST, "bob3"));
//        app.sign(CAROL, PdfSigner.CERTIFIED_NO_CHANGES_ALLOWED, String.format(DEST, "bob3"), "sig3", String.format(DEST, "carol3"));
//
//        app.sign(ALICE, PdfSigner.CERTIFIED_FORM_FILLING, FORM, "sig1", String.format(DEST, "alice4"));
//        app.sign(BOB, PdfSigner.NOT_CERTIFIED, String.format(DEST, "alice4"), "sig2", String.format(DEST, "bob4"));
//        app.sign(CAROL, PdfSigner.CERTIFIED_FORM_FILLING, String.format(DEST, "bob4"), "sig3", String.format(DEST, "carol4"));
    }

    @Test
    public void runTest() throws IOException, InterruptedException, GeneralSecurityException {
        new File("./target/test/resources/signatures/chapter02/").mkdirs();
        C2_10_SequentialSignatures.main(null);
//
//        String[] resultFiles =
//                new String[]{"signed_by_alice.pdf", "signed_by_bob.pdf", "signed_by_carol.pdf",
//                        "signed_by_alice2.pdf", "signed_by_bob2.pdf", "signed_by_carol2.pdf",
//                        "signed_by_alice3.pdf", "signed_by_bob3.pdf", "signed_by_carol3.pdf"};
//
//        String destPath = String.format(outPath, "chapter02");
//        String comparePath = String.format(cmpPath, "chapter02");
//
//        String[] errors = new String[resultFiles.length];
//        boolean error = false;
//
//        HashMap<Integer, List<Rectangle>> ignoredAreas = new HashMap<Integer, List<Rectangle>>() {
//            {
//                put(1, Arrays.asList(new Rectangle(46, 472, 287, 255)));
//            }
//        };
//
//        for (int i = 0; i < resultFiles.length; i++) {
//            String resultFile = resultFiles[i];
//            String fileErrors = checkForErrors(destPath + resultFile, comparePath + "cmp_" + resultFile, destPath, ignoredAreas);
//            if (fileErrors != null) {
//                errors[i] = fileErrors;
//                error = true;
//            }
//        }
//
//        if (error) {
//            fail(accumulateErrors(errors));
//        }
    }
}