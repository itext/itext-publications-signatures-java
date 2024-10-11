package com.itextpdf.samples.signatures.chapter02;

import com.itextpdf.forms.form.element.SignatureFieldAppearance;
import com.itextpdf.io.font.PdfEncodings;
import com.itextpdf.io.font.constants.StandardFonts;
import com.itextpdf.io.image.ImageData;
import com.itextpdf.io.image.ImageDataFactory;
import com.itextpdf.kernel.crypto.DigestAlgorithms;
import com.itextpdf.kernel.font.PdfFontFactory;
import com.itextpdf.kernel.font.PdfFontFactory.EmbeddingStrategy;
import com.itextpdf.kernel.pdf.PdfReader;
import com.itextpdf.kernel.pdf.StampingProperties;
import com.itextpdf.kernel.pdf.xobject.PdfImageXObject;
import com.itextpdf.layout.element.Div;
import com.itextpdf.layout.element.Paragraph;
import com.itextpdf.layout.element.Text;
import com.itextpdf.layout.properties.BackgroundImage;
import com.itextpdf.layout.properties.BackgroundPosition;
import com.itextpdf.layout.properties.BackgroundRepeat;
import com.itextpdf.layout.properties.BackgroundSize;
import com.itextpdf.layout.properties.BaseDirection;
import com.itextpdf.layout.properties.TextAlignment;
import com.itextpdf.layout.properties.UnitValue;
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

public class C2_06_SignatureAppearance {
    public static final String DEST = "./target/signatures/chapter02/";

    public static final String KEYSTORE = "./src/test/resources/encryption/certificate.p12";
    public static final String SRC = "./src/test/resources/pdfs/hello_to_sign.pdf";
    public static final String IMG = "./src/test/resources/img/1t3xt.gif";

    public static final char[] PASSWORD = "testpassphrase".toCharArray();

    public static final String[] RESULT_FILES = new String[] {
            "signature_appearance1.pdf",
            "signature_appearance2.pdf",
            "signature_appearance3.pdf",
            "signature_appearance4.pdf"
    };

    public void sign1(String src, String name, String dest, Certificate[] chain, PrivateKey pk, String digestAlgorithm,
            String provider, PdfSigner.CryptoStandard subfilter, String reason, String location)
            throws GeneralSecurityException, IOException {
        PdfReader reader = new PdfReader(src);
        PdfSigner signer = new PdfSigner(reader, new FileOutputStream(dest), new StampingProperties());

        // Create the signature appearance
        SignerProperties signerProps = new SignerProperties()
            .setReason(reason)
            .setLocation(location);

        // This name corresponds to the name of the field that already exists in the document.
        signerProps.setFieldName(name);

        // Set the custom text and a custom font
        SignatureFieldAppearance appearance = new SignatureFieldAppearance(SignerProperties.IGNORED_ID);
        appearance.setContent("This document was signed by Bruno Specimen");
        appearance.setFont(PdfFontFactory.createFont(StandardFonts.TIMES_ROMAN));
        signerProps.setSignatureAppearance(appearance);
        signer.setSignerProperties(signerProps);

        IExternalSignature pks = new PrivateKeySignature(pk, digestAlgorithm, provider);
        IExternalDigest digest = new BouncyCastleDigest();

        // Sign the document using the detached mode, CMS or CAdES equivalent.
        signer.signDetached(digest, pks, chain, null, null, null, 0, subfilter);
    }

    public void sign2(String src, String name, String dest, Certificate[] chain, PrivateKey pk, String digestAlgorithm,
            String provider, PdfSigner.CryptoStandard subfilter, String reason, String location)
            throws GeneralSecurityException, IOException {
        PdfReader reader = new PdfReader(src);
        PdfSigner signer = new PdfSigner(reader, new FileOutputStream(dest), new StampingProperties());

        SignerProperties signerProps = new SignerProperties()
                .setReason(reason)
                .setLocation(location)
                .setFieldName(name);

        // Creating the appearance for layer 2
        // Set custom text, custom font, and right-to-left writing.
        // Characters: لورانس العرب
        Text text = new Text("\u0644\u0648\u0631\u0627\u0646\u0633 \u0627\u0644\u0639\u0631\u0628");
        text.setFont(PdfFontFactory.createFont("./src/test/resources/font/NotoNaskhArabic-Regular.ttf",
                PdfEncodings.IDENTITY_H, EmbeddingStrategy.PREFER_EMBEDDED));
        text.setBaseDirection(BaseDirection.RIGHT_TO_LEFT);
        SignatureFieldAppearance appearance = new SignatureFieldAppearance(SignerProperties.IGNORED_ID);
        appearance.setContent(new Div().add(new Paragraph(text).setTextAlignment(TextAlignment.RIGHT)));
        signerProps.setSignatureAppearance(appearance);
        signer.setSignerProperties(signerProps);

        PrivateKeySignature pks = new PrivateKeySignature(pk, digestAlgorithm, provider);
        IExternalDigest digest = new BouncyCastleDigest();
        signer.signDetached(digest, pks, chain, null, null, null, 0, subfilter);
    }

    public void sign3(String src, String name, String dest, Certificate[] chain, PrivateKey pk, String digestAlgorithm,
            String provider, PdfSigner.CryptoStandard subfilter, String reason, String location)
            throws GeneralSecurityException, IOException {
        PdfReader reader = new PdfReader(src);
        PdfSigner signer = new PdfSigner(reader, new FileOutputStream(dest), new StampingProperties());

        SignerProperties signerProps = new SignerProperties()
                .setReason(reason)
                .setLocation(location)
                .setFieldName(name);

        // Set a custom text and a background image
        ImageData imageData = ImageDataFactory.create(IMG);
        SignatureFieldAppearance appearance = new SignatureFieldAppearance(SignerProperties.IGNORED_ID);
        appearance.setContent("This document was signed by Bruno Specimen");
        BackgroundSize size = new BackgroundSize();
        size.setBackgroundSizeToValues(UnitValue.createPointValue(imageData.getWidth()),
                UnitValue.createPointValue(imageData.getHeight()));
        BackgroundPosition backgroundPosition = new BackgroundPosition();
        backgroundPosition.setPositionX(BackgroundPosition.PositionX.CENTER)
                .setPositionY(BackgroundPosition.PositionY.CENTER);
        appearance.setBackgroundImage(new BackgroundImage.Builder()
                .setImage(new PdfImageXObject(imageData))
                .setBackgroundRepeat(new BackgroundRepeat(BackgroundRepeat.BackgroundRepeatValue.NO_REPEAT))
                .setBackgroundPosition(backgroundPosition)
                .setBackgroundSize(size).build());
        signerProps.setSignatureAppearance(appearance);
        signer.setSignerProperties(signerProps);

        PrivateKeySignature pks = new PrivateKeySignature(pk, digestAlgorithm, provider);
        IExternalDigest digest = new BouncyCastleDigest();
        signer.signDetached(digest, pks, chain, null, null, null, 0, subfilter);
    }

    public void sign4(String src, String name, String dest, Certificate[] chain, PrivateKey pk, String digestAlgorithm,
            String provider, PdfSigner.CryptoStandard subfilter, String reason, String location)
            throws GeneralSecurityException, IOException {
        PdfReader reader = new PdfReader(src);
        PdfSigner signer = new PdfSigner(reader, new FileOutputStream(dest), new StampingProperties());

        SignerProperties signerProps = new SignerProperties()
                .setReason(reason)
                .setLocation(location)
                .setFieldName(name);

        // Set a custom text and a scaled background image
        SignatureFieldAppearance appearance = new SignatureFieldAppearance(SignerProperties.IGNORED_ID);
        appearance.setContent("This document was signed by Bruno Specimen");
        BackgroundSize backgroundSize = new BackgroundSize();
        backgroundSize.setBackgroundSizeToContain();
        BackgroundPosition backgroundPosition = new BackgroundPosition();
        backgroundPosition.setPositionX(BackgroundPosition.PositionX.CENTER)
                .setPositionY(BackgroundPosition.PositionY.CENTER);
        appearance.setBackgroundImage(new BackgroundImage.Builder()
                .setImage(new PdfImageXObject(ImageDataFactory.create(IMG)))
                .setBackgroundRepeat(new BackgroundRepeat(BackgroundRepeat.BackgroundRepeatValue.NO_REPEAT))
                .setBackgroundPosition(backgroundPosition).setBackgroundSize(backgroundSize).build());
        signerProps.setSignatureAppearance(appearance);
        signer.setSignerProperties(signerProps);

        PrivateKeySignature pks = new PrivateKeySignature(pk, digestAlgorithm, provider);
        IExternalDigest digest = new BouncyCastleDigest();
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

        C2_06_SignatureAppearance app = new C2_06_SignatureAppearance();
        String signatureName = "Signature1";
        String signatureReason = "Custom appearance example";
        String location = "Ghent";
        app.sign1(SRC, signatureName, DEST + RESULT_FILES[0], chain, pk,
                DigestAlgorithms.SHA256, provider.getName(), PdfSigner.CryptoStandard.CMS,
                signatureReason, location);

        app.sign2(SRC, signatureName, DEST + RESULT_FILES[1], chain, pk,
                DigestAlgorithms.SHA256, provider.getName(), PdfSigner.CryptoStandard.CMS,
                signatureReason, location);

        app.sign3(SRC, signatureName, DEST + RESULT_FILES[2], chain, pk,
                DigestAlgorithms.SHA256, provider.getName(), PdfSigner.CryptoStandard.CMS,
                signatureReason, location);

        app.sign4(SRC, signatureName, DEST + RESULT_FILES[3], chain, pk,
                DigestAlgorithms.SHA256, provider.getName(), PdfSigner.CryptoStandard.CMS,
                signatureReason, location);
    }
}
