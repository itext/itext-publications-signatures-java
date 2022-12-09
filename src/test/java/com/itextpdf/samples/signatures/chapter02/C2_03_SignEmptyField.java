package com.itextpdf.samples.signatures.chapter02;

import com.itextpdf.kernel.pdf.PdfReader;
import com.itextpdf.kernel.pdf.StampingProperties;
import com.itextpdf.signatures.BouncyCastleDigest;
import com.itextpdf.signatures.DigestAlgorithms;
import com.itextpdf.signatures.IExternalDigest;
import com.itextpdf.signatures.IExternalSignature;
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

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class C2_03_SignEmptyField {
    public static final String DEST = "./target/signatures/chapter02/";

    public static final String KEYSTORE = "./src/test/resources/encryption/ks";
    public static final String SRC = "./src/test/resources/pdfs/hello_to_sign.pdf";

    public static final char[] PASSWORD = "password".toCharArray();

    public static final String[] RESULT_FILES = new String[] {
            "field_signed1.pdf",
            "field_signed2.pdf",
            "field_signed3.pdf",
            "field_signed4.pdf"
    };

    public void sign(String src, String name, String dest, Certificate[] chain, PrivateKey pk, String digestAlgorithm,
            String provider, PdfSigner.CryptoStandard subfilter, String reason, String location)
            throws GeneralSecurityException, IOException {
        PdfReader reader = new PdfReader(src);
        PdfSigner signer = new PdfSigner(reader, new FileOutputStream(dest), new StampingProperties());

        // Create the signature appearance
        signer.getSignatureAppearance()
                .setReason(reason)
                .setLocation(location)

                // Specify if the appearance before field is signed will be used
                // as a background for the signed field. The "false" value is the default value.
                .setReuseAppearance(false);

        // This name corresponds to the name of the field that already exists in the document.
        signer.setFieldName(name);

        IExternalSignature pks = new PrivateKeySignature(pk, digestAlgorithm, provider);
        IExternalDigest digest = new BouncyCastleDigest();

        // Sign the document using the detached mode, CMS or CAdES equivalent.
        signer.signDetached(digest, pks, chain, null, null, null, 0, subfilter);
    }

    public static void main(String[] args) throws GeneralSecurityException, IOException {
        File file = new File(DEST);
        file.mkdirs();

        BouncyCastleProvider provider = new BouncyCastleProvider();
        Security.addProvider(provider);
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        ks.load(new FileInputStream(KEYSTORE), PASSWORD);
        String alias = ks.aliases().nextElement();
        PrivateKey pk = (PrivateKey) ks.getKey(alias, PASSWORD);
        Certificate[] chain = ks.getCertificateChain(alias);

        C2_03_SignEmptyField app = new C2_03_SignEmptyField();
        app.sign(SRC, "Signature1", DEST + RESULT_FILES[0], chain, pk, DigestAlgorithms.SHA256,
                provider.getName(), PdfSigner.CryptoStandard.CMS, "Test 1", "Ghent");
        app.sign(SRC, "Signature1", DEST + RESULT_FILES[1], chain, pk, DigestAlgorithms.SHA512,
                provider.getName(), PdfSigner.CryptoStandard.CMS, "Test 2", "Ghent");
        app.sign(SRC, "Signature1", DEST + RESULT_FILES[2], chain, pk, DigestAlgorithms.SHA256,
                provider.getName(), PdfSigner.CryptoStandard.CADES, "Test 3", "Ghent");
        app.sign(SRC, "Signature1", DEST + RESULT_FILES[3], chain, pk, DigestAlgorithms.RIPEMD160,
                provider.getName(), PdfSigner.CryptoStandard.CADES, "Test 4", "Ghent");
    }
}
