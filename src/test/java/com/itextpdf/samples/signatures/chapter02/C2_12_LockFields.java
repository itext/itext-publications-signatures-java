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

import com.itextpdf.forms.PdfAcroForm;
import com.itextpdf.forms.PdfSigFieldLock;
import com.itextpdf.forms.fields.PdfFormField;
import com.itextpdf.kernel.pdf.PdfDocument;
import com.itextpdf.kernel.pdf.PdfName;
import com.itextpdf.kernel.pdf.PdfReader;
import com.itextpdf.kernel.pdf.PdfWriter;
import com.itextpdf.kernel.pdf.StampingProperties;
import com.itextpdf.kernel.pdf.annot.PdfAnnotation;
import com.itextpdf.layout.Document;
import com.itextpdf.layout.element.Cell;
import com.itextpdf.layout.element.Table;
import com.itextpdf.layout.property.UnitValue;
import com.itextpdf.layout.renderer.CellRenderer;
import com.itextpdf.layout.renderer.DrawContext;
import com.itextpdf.signatures.BouncyCastleDigest;
import com.itextpdf.signatures.DigestAlgorithms;
import com.itextpdf.signatures.IExternalDigest;
import com.itextpdf.signatures.PdfSigner;
import com.itextpdf.signatures.PrivateKeySignature;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;

public class C2_12_LockFields {
    public static final String DEST = "./target/signatures/chapter02/";
    public static final String FORM = "./target/signatures/chapter02/form_lock.pdf";

    public static final String ALICE = "./src/test/resources/encryption/alice";
    public static final String BOB = "./src/test/resources/encryption/bob";
    public static final String CAROL = "./src/test/resources/encryption/carol";
    public static final String DAVE = "./src/test/resources/encryption/dave";
    public static final String KEYSTORE = "./src/test/resources/encryption/ks";

    public static final char[] PASSWORD = "password".toCharArray();

    public static final String[] RESULT_FILES = new String[] {
            "step_1_signed_by_alice.pdf", "step_2_signed_by_alice_and_bob.pdf",
            "step_3_signed_by_alice_bob_and_carol.pdf", "step_4_signed_by_alice_bob_carol_and_dave.pdf",
            "step_5_signed_by_alice_and_bob_broken_by_chuck.pdf", "step_6_signed_by_dave_broken_by_chuck.pdf"
    };

    public static void main(String[] args) throws IOException, GeneralSecurityException {
        File file = new File(DEST);
        file.mkdirs();

        BouncyCastleProvider provider = new BouncyCastleProvider();
        Security.addProvider(provider);

        C2_12_LockFields app = new C2_12_LockFields();
        app.createForm();

        app.certify(ALICE, provider.getName(), FORM, "sig1", DEST + RESULT_FILES[0]);
        app.fillOutAndSign(BOB, provider.getName(), DEST + RESULT_FILES[0], "sig2", "approved_bob",
                "Read and Approved by Bob", DEST + RESULT_FILES[1]);
        app.fillOutAndSign(CAROL, provider.getName(), DEST + RESULT_FILES[1], "sig3", "approved_carol",
                "Read and Approved by Carol", DEST + RESULT_FILES[2]);
        app.fillOutAndSign(DAVE, provider.getName(), DEST + RESULT_FILES[2], "sig4", "approved_dave",
                "Read and Approved by Dave", DEST + RESULT_FILES[3]);
        app.fillOut(DEST + RESULT_FILES[1], DEST + RESULT_FILES[4],
                "approved_bob", "Changed by Chuck");
        app.fillOut(DEST + RESULT_FILES[3], DEST + RESULT_FILES[5],
                "approved_carol", "Changed by Chuck");
    }

    public void createForm() throws IOException {
        PdfDocument pdfDoc = new PdfDocument(new PdfWriter(FORM));
        Document doc = new Document(pdfDoc);

        Table table = new Table(UnitValue.createPercentArray(1)).useAllAvailableWidth();
        table.addCell("Written by Alice");
        table.addCell(createSignatureFieldCell("sig1", null));
        table.addCell("For approval by Bob");
        table.addCell(createTextFieldCell("approved_bob"));

        PdfSigFieldLock lock = new PdfSigFieldLock()
                .setFieldLock(PdfSigFieldLock.LockAction.INCLUDE, "sig1", "approved_bob", "sig2");
        table.addCell(createSignatureFieldCell("sig2", lock));
        table.addCell("For approval by Carol");
        table.addCell(createTextFieldCell("approved_carol"));

        lock = new PdfSigFieldLock().setFieldLock(PdfSigFieldLock.LockAction.EXCLUDE, "approved_dave", "sig4");
        table.addCell(createSignatureFieldCell("sig3", lock));
        table.addCell("For approval by Dave");
        table.addCell(createTextFieldCell("approved_dave"));

        lock = new PdfSigFieldLock().setDocumentPermissions(PdfSigFieldLock.LockPermissions.NO_CHANGES_ALLOWED);
        table.addCell(createSignatureFieldCell("sig4", lock));
        doc.add(table);

        doc.close();
    }

    public void certify(String keystore, String provider, String src, String name, String dest)
            throws GeneralSecurityException, IOException {
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        ks.load(new FileInputStream(keystore), PASSWORD);
        String alias = ks.aliases().nextElement();
        PrivateKey pk = (PrivateKey) ks.getKey(alias, PASSWORD);
        Certificate[] chain = ks.getCertificateChain(alias);

        PdfReader reader = new PdfReader(src);
        PdfSigner signer = new PdfSigner(reader, new FileOutputStream(dest), new StampingProperties().useAppendMode());

        // Set signer options
        signer.setFieldName(name);
        signer.setCertificationLevel(PdfSigner.CERTIFIED_FORM_FILLING);

        PdfAcroForm form = PdfAcroForm.getAcroForm(signer.getDocument(), true);
        form.getField(name).setReadOnly(true);

        PrivateKeySignature pks = new PrivateKeySignature(pk, DigestAlgorithms.SHA256, provider);
        IExternalDigest digest = new BouncyCastleDigest();

        // Sign the document using the detached mode, CMS or CAdES equivalent.
        signer.signDetached(digest, pks, chain, null, null, null,
                0, PdfSigner.CryptoStandard.CMS);
    }

    public void fillOutAndSign(String keystore, String provider, String src, String name, String fname, String value,
            String dest)
            throws GeneralSecurityException, IOException {
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        ks.load(new FileInputStream(keystore), PASSWORD);
        String alias = ks.aliases().nextElement();
        PrivateKey pk = (PrivateKey) ks.getKey(alias, PASSWORD);
        Certificate[] chain = ks.getCertificateChain(alias);

        PdfReader reader = new PdfReader(src);
        PdfSigner signer = new PdfSigner(reader, new FileOutputStream(dest), new StampingProperties().useAppendMode());
        signer.setFieldName(name);

        PdfAcroForm form = PdfAcroForm.getAcroForm(signer.getDocument(), true);
        form.getField(fname).setValue(value);
        form.getField(name).setReadOnly(true);
        form.getField(fname).setReadOnly(true);

        PrivateKeySignature pks = new PrivateKeySignature(pk, DigestAlgorithms.SHA256, provider);
        IExternalDigest digest = new BouncyCastleDigest();
        signer.signDetached(digest, pks, chain, null, null, null,
                0, PdfSigner.CryptoStandard.CMS);
    }

    public void fillOut(String src, String dest, String name, String value) throws IOException {
        PdfDocument pdfDoc = new PdfDocument(new PdfReader(src), new PdfWriter(dest),
                new StampingProperties().useAppendMode());

        PdfAcroForm form = PdfAcroForm.getAcroForm(pdfDoc, true);
        form.getField(name).setValue(value);

        pdfDoc.close();
    }

    public void sign(String keystore, String provider, String src, String name, String dest)
            throws GeneralSecurityException, IOException {
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        ks.load(new FileInputStream(keystore), PASSWORD);
        String alias = ks.aliases().nextElement();
        PrivateKey pk = (PrivateKey) ks.getKey(alias, PASSWORD);
        Certificate[] chain = ks.getCertificateChain(alias);

        PdfReader reader = new PdfReader(src);
        PdfSigner signer = new PdfSigner(reader, new FileOutputStream(dest), new StampingProperties().useAppendMode());
        signer.setFieldName(name);

        PrivateKeySignature pks = new PrivateKeySignature(pk, DigestAlgorithms.SHA256, provider);
        IExternalDigest digest = new BouncyCastleDigest();
        signer.signDetached(digest, pks, chain, null, null, null,
                0, PdfSigner.CryptoStandard.CMS);
    }

    protected static Cell createTextFieldCell(String name) {
        Cell cell = new Cell();
        cell.setHeight(20);
        cell.setNextRenderer(new TextFieldCellRenderer(cell, name));
        return cell;
    }

    protected static Cell createSignatureFieldCell(String name, PdfSigFieldLock lock) throws IOException {
        Cell cell = new Cell();
        cell.setHeight(50);
        cell.setNextRenderer(new SignatureFieldCellRenderer(cell, name, lock));
        return cell;
    }


    private static class TextFieldCellRenderer extends CellRenderer {
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


    private static class SignatureFieldCellRenderer extends CellRenderer {
        public String name;
        public PdfSigFieldLock lock;

        public SignatureFieldCellRenderer(Cell modelElement, String name, PdfSigFieldLock lock) {
            super(modelElement);
            this.name = name;
            this.lock = lock;
        }

        @Override
        public void draw(DrawContext drawContext) {
            super.draw(drawContext);
            PdfFormField field = PdfFormField.createSignature(drawContext.getDocument(), getOccupiedAreaBBox());
            field.setFieldName(name);
            if (lock != null) {
                field.put(PdfName.Lock, lock.makeIndirect(drawContext.getDocument()).getPdfObject());
            }

            field.getWidgets().get(0).setFlag(PdfAnnotation.PRINT);
            field.getWidgets().get(0).setHighlightMode(PdfAnnotation.HIGHLIGHT_INVERT);
            PdfAcroForm.getAcroForm(drawContext.getDocument(), true).addField(field);
        }
    }
}
