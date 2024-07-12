package com.itextpdf.samples.signatures.chapter02;

import com.itextpdf.forms.PdfAcroForm;
import com.itextpdf.forms.fields.PdfFormField;
import com.itextpdf.forms.fields.PdfSignatureFormField;
import com.itextpdf.forms.fields.SignatureFormFieldBuilder;
import com.itextpdf.kernel.colors.ColorConstants;
import com.itextpdf.kernel.geom.Rectangle;
import com.itextpdf.kernel.pdf.PdfReader;
import com.itextpdf.kernel.pdf.PdfDocument;
import com.itextpdf.kernel.pdf.PdfWriter;
import com.itextpdf.kernel.pdf.PdfDictionary;
import com.itextpdf.kernel.pdf.PdfArray;
import com.itextpdf.kernel.pdf.PdfNumber;
import com.itextpdf.kernel.pdf.PdfName;
import com.itextpdf.kernel.pdf.StampingProperties;
import com.itextpdf.kernel.pdf.annot.PdfAnnotation;
import com.itextpdf.kernel.pdf.canvas.PdfCanvas;
import com.itextpdf.kernel.pdf.xobject.PdfFormXObject;
import com.itextpdf.layout.Canvas;
import com.itextpdf.layout.Document;
import com.itextpdf.layout.element.Paragraph;
import com.itextpdf.layout.properties.TextAlignment;
import com.itextpdf.signatures.BouncyCastleDigest;
import com.itextpdf.signatures.DigestAlgorithms;
import com.itextpdf.signatures.IExternalDigest;
import com.itextpdf.signatures.IExternalSignature;
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

public class C2_04_CreateEmptyField {
    public static final String DEST = "./target/signatures/chapter02/";

    public static final String KEYSTORE = "./src/test/resources/encryption/certificate.p12";
    public static final String SRC = "./src/test/resources/pdfs/hello.pdf";

    public static final char[] PASSWORD = "testpassphrase".toCharArray();
    public static final String SIGNAME = "Signature1";

    public static final String[] RESULT_FILES = new String[]{
            "hello_empty.pdf",
            "hello_empty2.pdf",
            "field_signed.pdf"
    };

    public void createPdf(String filename) throws IOException {
        PdfDocument pdfDoc = new PdfDocument(new PdfWriter(filename));
        Document doc = new Document(pdfDoc);

        doc.add(new Paragraph("Hello World!"));

        // Create a signature form field
        PdfFormField field = new SignatureFormFieldBuilder(pdfDoc, SIGNAME)
                .setWidgetRectangle(new Rectangle(72, 632, 200, 100)).createSignature();
        field.getFirstFormAnnotation().setPage(1);

        // Set the widget properties
        field.getWidgets().get(0).setHighlightMode(PdfAnnotation.HIGHLIGHT_INVERT).setFlags(PdfAnnotation.PRINT);

        PdfDictionary mkDictionary = field.getWidgets().get(0).getAppearanceCharacteristics();
        if (null == mkDictionary) {
            mkDictionary = new PdfDictionary();
        }

        PdfArray black = new PdfArray();
        black.add(new PdfNumber(ColorConstants.BLACK.getColorValue()[0]));
        black.add(new PdfNumber(ColorConstants.BLACK.getColorValue()[1]));
        black.add(new PdfNumber(ColorConstants.BLACK.getColorValue()[2]));
        mkDictionary.put(PdfName.BC, black);

        field.getWidgets().get(0).setAppearanceCharacteristics(mkDictionary);

        PdfAcroForm.getAcroForm(pdfDoc, true).addField(field);

        Rectangle rect = new Rectangle(0, 0, 200, 100);
        PdfFormXObject xObject = new PdfFormXObject(rect);
        PdfCanvas canvas = new PdfCanvas(xObject, pdfDoc);
        canvas
                .setStrokeColor(ColorConstants.BLUE)
                .setFillColor(ColorConstants.LIGHT_GRAY)
                .rectangle(0 + 0.5, 0 + 0.5, 200 - 0.5, 100 - 0.5)
                .fillStroke()
                .setFillColor(ColorConstants.BLUE);
        new Canvas(canvas, rect).showTextAligned("SIGN HERE", 100, 50,
                TextAlignment.CENTER, (float) Math.toRadians(25));

        // Note that Acrobat doesn't show normal appearance in the highlight mode.
        field.getWidgets().get(0).setNormalAppearance(xObject.getPdfObject());

        doc.close();
    }

    public void addField(String src, String dest) throws IOException {
        PdfDocument pdfDoc = new PdfDocument(new PdfReader(src), new PdfWriter(dest));

        // Create a signature form field
        PdfSignatureFormField field = new SignatureFormFieldBuilder(pdfDoc, SIGNAME)
                .setWidgetRectangle(new Rectangle(72, 632, 200, 100)).createSignature();

        field.getWidgets().get(0).setHighlightMode(PdfAnnotation.HIGHLIGHT_OUTLINE).setFlags(PdfAnnotation.PRINT);

        PdfAcroForm.getAcroForm(pdfDoc, true).addField(field);

        pdfDoc.close();
    }

    public void sign(String src, String name, String dest, Certificate[] chain, PrivateKey pk, String digestAlgorithm,
                     String provider, PdfSigner.CryptoStandard subfilter, String reason, String location)
            throws GeneralSecurityException, IOException {
        PdfReader reader = new PdfReader(src);
        PdfSigner signer = new PdfSigner(reader, new FileOutputStream(dest), new StampingProperties());

        signer.setReason(reason);
        signer.setLocation(location);

        signer.setFieldName(name);

        IExternalSignature pks = new PrivateKeySignature(pk, digestAlgorithm, provider);
        IExternalDigest digest = new BouncyCastleDigest();

        // Sign the document using the detached mode, CMS or CAdES equivalent.
        signer.signDetached(digest, pks, chain, null, null, null, 0, subfilter);
    }

    public static void main(String[] args) throws IOException, GeneralSecurityException {
        File file = new File(DEST);
        file.mkdirs();

        C2_04_CreateEmptyField app = new C2_04_CreateEmptyField();
        app.createPdf(DEST + RESULT_FILES[0]);
        app.addField(SRC, DEST + RESULT_FILES[1]);

        BouncyCastleProvider provider = new BouncyCastleProvider();
        Security.addProvider(provider);
        KeyStore ks = KeyStore.getInstance("pkcs12", provider.getName());
        ks.load(new FileInputStream(KEYSTORE), PASSWORD);
        String alias = ks.aliases().nextElement();
        PrivateKey pk = (PrivateKey) ks.getKey(alias, PASSWORD);
        Certificate[] chain = ks.getCertificateChain(alias);

        app.sign(DEST + RESULT_FILES[0], SIGNAME, DEST + RESULT_FILES[2], chain, pk,
                DigestAlgorithms.SHA256, provider.getName(), PdfSigner.CryptoStandard.CMS,
                "Test", "Ghent");
    }
}
