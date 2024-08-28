package com.itextpdf.samples.signatures.chapter02;

import com.itextpdf.kernel.colors.ColorConstants;
import com.itextpdf.kernel.geom.Rectangle;
import com.itextpdf.kernel.pdf.PdfReader;
import com.itextpdf.kernel.pdf.StampingProperties;
import com.itextpdf.kernel.pdf.canvas.PdfCanvas;
import com.itextpdf.kernel.pdf.xobject.PdfFormXObject;
import com.itextpdf.layout.Canvas;
import com.itextpdf.layout.element.Paragraph;
import com.itextpdf.signatures.BouncyCastleDigest;
import com.itextpdf.signatures.DigestAlgorithms;
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

public class C2_05_CustomAppearance {
    public static final String DEST = "./target/signatures/chapter02/";

    public static final String KEYSTORE = "./src/test/resources/encryption/certificate.p12";
    public static final String SRC = "./src/test/resources/pdfs/hello_to_sign.pdf";

    public static final char[] PASSWORD = "testpassphrase".toCharArray();

    public static final String[] RESULT_FILES = new String[] {
            "signature_custom.pdf"
    };

    public void sign(String src, String name, String dest, Certificate[] chain, PrivateKey pk, String digestAlgorithm,
            String provider,
            PdfSigner.CryptoStandard subfilter,
            String reason, String location)
            throws GeneralSecurityException, IOException {
        PdfReader reader = new PdfReader(src);
        PdfSigner signer = new PdfSigner(reader, new FileOutputStream(dest), new StampingProperties());

        // This name corresponds to the name of the field that already exists in the document.
        signer.setSignerProperties(new SignerProperties().setFieldName(name));

        // Create the signature appearance
        signer.getSignerProperties()
                .setReason(reason)
                .setLocation(location);

        Rectangle widget = signer.getSignatureField().getFirstFormAnnotation().getWidget().getRectangle().toRectangle();
        Rectangle signatureRect = new Rectangle(0, 0, widget.getWidth(),
                widget.getHeight());

        // Get the background layer and draw a gray rectangle as a background.
        PdfFormXObject backgroundLayer = new PdfFormXObject(
                new Rectangle(signatureRect));
        PdfCanvas canvas = new PdfCanvas(backgroundLayer, signer.getDocument());
        canvas.setFillColor(ColorConstants.LIGHT_GRAY);
        canvas.rectangle(new Rectangle(signatureRect));
        canvas.fill();

        PdfFormXObject foregroundLayer = new PdfFormXObject(signatureRect);
        new Canvas(foregroundLayer, signer.getDocument()).add(
                new Paragraph("This document was signed by Bruno Specimen."));

        signer.getSignatureField().setBackgroundLayer(backgroundLayer)
                .setSignatureAppearanceLayer(foregroundLayer);

        IExternalSignature pks = new PrivateKeySignature(pk, digestAlgorithm, provider);
        IExternalDigest digest = new BouncyCastleDigest();

        // Sign the document using the detached mode, CMS or CAdES equivalent.
        signer.signDetached(digest, pks, chain, null, null, null, 0, subfilter);
    }

    public static void main(String[] args) throws IOException, GeneralSecurityException {
        File file = new File(DEST);
        file.mkdirs();

        BouncyCastleProvider provider = new BouncyCastleProvider();
        Security.addProvider(provider);
        KeyStore ks = KeyStore.getInstance("pkcs12", provider.getName());
        ks.load(new FileInputStream(KEYSTORE), PASSWORD);
        String alias = ks.aliases().nextElement();
        PrivateKey pk = (PrivateKey) ks.getKey(alias, PASSWORD);
        Certificate[] chain = ks.getCertificateChain(alias);

        new C2_05_CustomAppearance().sign(SRC, "Signature1", DEST + RESULT_FILES[0], chain, pk,
                DigestAlgorithms.SHA256, provider.getName(), PdfSigner.CryptoStandard.CMS,
                "Custom appearance example", "Ghent");
    }
}
