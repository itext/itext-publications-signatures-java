package com.itextpdf.samples.signatures.chapter02;

import com.itextpdf.forms.PdfAcroForm;
import com.itextpdf.forms.fields.PdfFormField;
import com.itextpdf.forms.fields.SignatureFormFieldBuilder;
import com.itextpdf.kernel.crypto.DigestAlgorithms;
import com.itextpdf.kernel.pdf.PdfDocument;
import com.itextpdf.kernel.pdf.PdfReader;
import com.itextpdf.kernel.pdf.PdfWriter;
import com.itextpdf.kernel.pdf.StampingProperties;
import com.itextpdf.kernel.pdf.annot.PdfAnnotation;
import com.itextpdf.layout.Document;
import com.itextpdf.layout.element.Cell;
import com.itextpdf.layout.element.Table;
import com.itextpdf.layout.properties.UnitValue;
import com.itextpdf.layout.renderer.CellRenderer;
import com.itextpdf.layout.renderer.DrawContext;
import com.itextpdf.signatures.AccessPermissions;
import com.itextpdf.signatures.BouncyCastleDigest;
import com.itextpdf.signatures.IExternalDigest;
import com.itextpdf.signatures.IExternalSignature;
import com.itextpdf.signatures.PdfSigner;
import com.itextpdf.signatures.PrivateKeySignature;
import com.itextpdf.signatures.SignerProperties;

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

public class C2_10_SequentialSignatures {

    public static final String DEST = "./target/signatures/chapter02/";
    public static final String FORM = "./target/signatures/chapter02/multiple_signatures.pdf";

    public static final String ALICE = "./src/test/resources/encryption/alice.p12";
    public static final String BOB = "./src/test/resources/encryption/bob.p12";
    public static final String CAROL = "./src/test/resources/encryption/carol.p12";

    public static final char[] PASSWORD = "testpassphrase".toCharArray();

    public static final String[] RESULT_FILES = new String[] {
            "signed_by_alice.pdf", "signed_by_bob.pdf",
            "signed_by_carol.pdf", "signed_by_alice2.pdf",
            "signed_by_bob2.pdf", "signed_by_carol2.pdf",
            "signed_by_alice3.pdf", "signed_by_bob3.pdf",
            "signed_by_carol3.pdf", "signed_by_alice4.pdf",
            "signed_by_bob4.pdf", "signed_by_carol4.pdf",
    };

    public void createForm() throws IOException {
        PdfDocument pdfDoc = new PdfDocument(new PdfWriter(FORM));
        Document doc = new Document(pdfDoc);

        Table table = new Table(UnitValue.createPercentArray(1)).useAllAvailableWidth();
        table.addCell("Signer 1: Alice");
        table.addCell(createSignatureFieldCell("sig1"));
        table.addCell("Signer 2: Bob");
        table.addCell(createSignatureFieldCell("sig2"));
        table.addCell("Signer 3: Carol");
        table.addCell(createSignatureFieldCell("sig3"));
        doc.add(table);

        doc.close();
    }

    protected Cell createSignatureFieldCell(String name) {
        Cell cell = new Cell();
        cell.setHeight(50);
        cell.setNextRenderer(new SignatureFieldCellRenderer(cell, name));
        return cell;
    }

    public void sign(String keystore, String provider, AccessPermissions level, String src, String name, String dest)
            throws GeneralSecurityException, IOException {
        KeyStore ks = KeyStore.getInstance("pkcs12", provider);
        ks.load(new FileInputStream(keystore), PASSWORD);
        String alias = ks.aliases().nextElement();
        PrivateKey pk = (PrivateKey) ks.getKey(alias, PASSWORD);
        Certificate[] chain = ks.getCertificateChain(alias);

        PdfReader reader = new PdfReader(src);
        PdfSigner signer = new PdfSigner(reader, new FileOutputStream(dest), new StampingProperties().useAppendMode());

        // Set the signer options
        SignerProperties signerProperties = new SignerProperties()
                .setFieldName(name)
                .setCertificationLevel(level);
        signer.setSignerProperties(signerProperties);

        IExternalSignature pks = new PrivateKeySignature(pk, DigestAlgorithms.SHA256, provider);
        IExternalDigest digest = new BouncyCastleDigest();

        // Sign the document using the detached mode, CMS or CAdES equivalent.
        signer.signDetached(digest, pks, chain, null, null, null,
                0, PdfSigner.CryptoStandard.CMS);
    }

    public static void main(String[] args) throws IOException, GeneralSecurityException {
        File file = new File(DEST);
        file.mkdirs();

        BouncyCastleProvider provider = new BouncyCastleProvider();
        Security.addProvider(provider);

        C2_10_SequentialSignatures app = new C2_10_SequentialSignatures();
        app.createForm();

        /* Alice signs certification signature (allowing form filling),
         * then Bob and Carol sign approval signature (not certified).
         */
        app.sign(ALICE, provider.getName(), AccessPermissions.FORM_FIELDS_MODIFICATION, FORM, "sig1", DEST + RESULT_FILES[0]);
        app.sign(BOB, provider.getName(), AccessPermissions.UNSPECIFIED, DEST + RESULT_FILES[0], "sig2",
                DEST + RESULT_FILES[1]);
        app.sign(CAROL, provider.getName(), AccessPermissions.UNSPECIFIED, DEST + RESULT_FILES[1], "sig3",
                DEST + RESULT_FILES[2]);

        /* Alice signs approval signatures (not certified), so does Bob
         * and then Carol signs certification signature allowing form filling.
         */
        app.sign(ALICE, provider.getName(), AccessPermissions.UNSPECIFIED, FORM, "sig1", DEST + RESULT_FILES[3]);
        app.sign(BOB, provider.getName(), AccessPermissions.UNSPECIFIED, DEST + RESULT_FILES[3], "sig2",
                DEST + RESULT_FILES[4]);
        app.sign(CAROL, provider.getName(), AccessPermissions.FORM_FIELDS_MODIFICATION, DEST + RESULT_FILES[4], "sig3",
                DEST + RESULT_FILES[5]);

        /* Alice signs approval signatures (not certified), so does Bob
         * and then Carol signs certification signature forbidding any changes to the document.
         */
        app.sign(ALICE, provider.getName(), AccessPermissions.UNSPECIFIED, FORM, "sig1", DEST + RESULT_FILES[6]);
        app.sign(BOB, provider.getName(), AccessPermissions.UNSPECIFIED, DEST + RESULT_FILES[6], "sig2",
                DEST + RESULT_FILES[7]);
        app.sign(CAROL, provider.getName(), AccessPermissions.NO_CHANGES_PERMITTED, DEST + RESULT_FILES[7], "sig3",
                DEST + RESULT_FILES[8]);

        /* Alice signs certification signature (allowing form filling), then Bob signs approval
         * signatures (not certified) and then Carol signs certification signature allowing form filling.
         */
        app.sign(ALICE, provider.getName(), AccessPermissions.FORM_FIELDS_MODIFICATION, FORM, "sig1", DEST + RESULT_FILES[9]);
        app.sign(BOB, provider.getName(), AccessPermissions.UNSPECIFIED, DEST + RESULT_FILES[9], "sig2",
                DEST + RESULT_FILES[10]);
        app.sign(CAROL, provider.getName(), AccessPermissions.FORM_FIELDS_MODIFICATION, DEST + RESULT_FILES[10], "sig3",
                DEST + RESULT_FILES[11]);
    }

    private static class SignatureFieldCellRenderer extends CellRenderer {
        public String name;

        public SignatureFieldCellRenderer(Cell modelElement, String name) {
            super(modelElement);
            this.name = name;
        }

        @Override
        public void draw(DrawContext drawContext) {
            super.draw(drawContext);
            PdfFormField field = new SignatureFormFieldBuilder(drawContext.getDocument(), name)
                    .setWidgetRectangle(getOccupiedAreaBBox()).createSignature();
            field.getWidgets().get(0).setHighlightMode(PdfAnnotation.HIGHLIGHT_INVERT);
            field.getWidgets().get(0).setFlags(PdfAnnotation.PRINT);
            PdfAcroForm.getAcroForm(drawContext.getDocument(), true).addField(field);
        }
    }
}
