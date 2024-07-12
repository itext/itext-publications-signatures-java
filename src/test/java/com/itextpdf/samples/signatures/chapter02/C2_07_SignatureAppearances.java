package com.itextpdf.samples.signatures.chapter02;

import com.itextpdf.forms.form.element.SignatureFieldAppearance;
import com.itextpdf.io.image.ImageData;
import com.itextpdf.io.image.ImageDataFactory;
import com.itextpdf.kernel.pdf.PdfReader;
import com.itextpdf.kernel.pdf.StampingProperties;
import com.itextpdf.signatures.BouncyCastleDigest;
import com.itextpdf.signatures.DigestAlgorithms;
import com.itextpdf.signatures.IExternalDigest;
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
import java.text.SimpleDateFormat;

import java.util.Locale;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class C2_07_SignatureAppearances {
    public static final String DEST = "./target/signatures/chapter02/";

    public static final String KEYSTORE = "./src/test/resources/encryption/certificate.p12";
    public static final String SRC = "./src/test/resources/pdfs/hello_to_sign.pdf";
    public static final String IMG = "./src/test/resources/img/1t3xt.gif";

    public static final char[] PASSWORD = "testpassphrase".toCharArray();

    public static final String[] RESULT_FILES = new String[] {
            "signature_appearance_1.pdf",
            "signature_appearance_2.pdf",
            "signature_appearance_3.pdf",
            "signature_appearance_4.pdf"
    };

    public void sign1(String src, String name, String dest, Certificate[] chain, PrivateKey pk, String digestAlgorithm,
            String provider, PdfSigner.CryptoStandard subfilter, String reason, String location)
            throws GeneralSecurityException, IOException {
        PdfReader reader = new PdfReader(src);
        PdfSigner signer = new PdfSigner(reader, new FileOutputStream(dest), new StampingProperties());

        // Create the signature appearance
        signer
            .setReason(reason)
            .setLocation(location);

        // This name corresponds to the name of the field that already exists in the document.
        signer.setFieldName(name);

        //Only description is rendered
        SignatureFieldAppearance appearance = new SignatureFieldAppearance(signer.getFieldName());
        appearance.setContent("Signed by iText");
        signer.setSignatureAppearance(appearance);

        PrivateKeySignature pks = new PrivateKeySignature(pk, digestAlgorithm, provider);
        IExternalDigest digest = new BouncyCastleDigest();

        // Sign the document using the detached mode, CMS or CAdES equivalent.
        signer.signDetached(digest, pks, chain, null, null, null, 0, subfilter);
    }

    public void sign2(String src, String name, String dest, Certificate[] chain, PrivateKey pk, String digestAlgorithm,
            String provider, PdfSigner.CryptoStandard subfilter, String reason, String location)
            throws GeneralSecurityException, IOException {
        PdfReader reader = new PdfReader(src);
        PdfSigner signer = new PdfSigner(reader, new FileOutputStream(dest), new StampingProperties());

        // Create the signature appearance
        signer
            .setReason(reason)
            .setLocation(location);

        // This name corresponds to the name of the field that already exists in the document.
        signer.setFieldName(name);

        //Name and description is rendered
        SignatureFieldAppearance appearance = new SignatureFieldAppearance(signer.getFieldName());
        appearance.setContent("", "Signed by iText");
        signer.setSignatureAppearance(appearance);

        PrivateKeySignature pks = new PrivateKeySignature(pk, digestAlgorithm, provider);
        IExternalDigest digest = new BouncyCastleDigest();

        // Sign the document using the detached mode, CMS or CAdES equivalent.
        signer.signDetached(digest, pks, chain, null, null, null, 0, subfilter);
    }

    public void sign3(String src, String name, String dest, Certificate[] chain, PrivateKey pk, String digestAlgorithm,
            String provider, PdfSigner.CryptoStandard subfilter, String reason, String location,
            ImageData image)
            throws GeneralSecurityException, IOException {
        PdfReader reader = new PdfReader(src);
        PdfSigner signer = new PdfSigner(reader, new FileOutputStream(dest), new StampingProperties());

        // Create the signature appearance
        signer
                .setReason(reason)
                .setLocation(location);

        // This name corresponds to the name of the field that already exists in the document.
        signer.setFieldName(name);

        //Graphic and description is rendered
        SignatureFieldAppearance appearance = new SignatureFieldAppearance("Signature1");
        appearance.setContent("Signed by iText", image);
        signer.setSignatureAppearance(appearance);

        PrivateKeySignature pks = new PrivateKeySignature(pk, digestAlgorithm, provider);
        IExternalDigest digest = new BouncyCastleDigest();

        // Sign the document using the detached mode, CMS or CAdES equivalent.
        signer.signDetached(digest, pks, chain, null, null, null, 0, subfilter);
    }

    public void sign4(String src, String name, String dest, Certificate[] chain, PrivateKey pk, String digestAlgorithm,
            String provider, PdfSigner.CryptoStandard subfilter, String reason, String location,
            ImageData image)
            throws GeneralSecurityException, IOException {
        PdfReader reader = new PdfReader(src);
        PdfSigner signer = new PdfSigner(reader, new FileOutputStream(dest), new StampingProperties());

        // Create the signature appearance
        signer
            .setReason(reason)
            .setLocation(location);

        // This name corresponds to the name of the field that already exists in the document.
        signer.setFieldName(name);

        //Graphic is rendered
        SignatureFieldAppearance appearance = new SignatureFieldAppearance("Signature1");
        appearance.setContent(image);
        signer.setSignatureAppearance(appearance);

        PrivateKeySignature pks = new PrivateKeySignature(pk, digestAlgorithm, provider);
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
        ImageData image = ImageDataFactory.create(IMG);

        C2_07_SignatureAppearances app = new C2_07_SignatureAppearances();
        String signatureName = "Signature1";
        String location = "Ghent";
        app.sign1(SRC, signatureName, DEST + RESULT_FILES[0], chain, pk,
                DigestAlgorithms.SHA256, provider.getName(), PdfSigner.CryptoStandard.CMS,
                "Appearance 1", location);

        app.sign2(SRC, signatureName, DEST + RESULT_FILES[1], chain, pk,
                DigestAlgorithms.SHA256, provider.getName(), PdfSigner.CryptoStandard.CMS,
                "Appearance 2", location);

        app.sign3(SRC, signatureName, DEST + RESULT_FILES[2], chain, pk,
                DigestAlgorithms.SHA256, provider.getName(), PdfSigner.CryptoStandard.CMS,
                "Appearance 3", location, image);

        app.sign4(SRC, signatureName, DEST + RESULT_FILES[3], chain, pk,
                DigestAlgorithms.SHA256, provider.getName(), PdfSigner.CryptoStandard.CMS,
                "Appearance 4", location, image);
    }
}
