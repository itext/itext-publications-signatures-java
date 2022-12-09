package com.itextpdf.samples.signatures.chapter02;

import com.itextpdf.kernel.geom.Rectangle;
import com.itextpdf.kernel.pdf.PdfReader;
import com.itextpdf.kernel.pdf.StampingProperties;
import com.itextpdf.signatures.PdfSigner;
import com.itextpdf.signatures.PdfSignatureAppearance;
import com.itextpdf.signatures.IExternalSignature;
import com.itextpdf.signatures.IExternalDigest;
import com.itextpdf.signatures.PrivateKeySignature;
import com.itextpdf.signatures.BouncyCastleDigest;
import com.itextpdf.signatures.DigestAlgorithms;

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

public class C2_02_SignHelloWorldWithTempFile {
    public static final String DEST = "./target/signatures/chapter02/";

    public static final String KEYSTORE = "./src/test/resources/encryption/ks";
    public static final String SRC = "./src/test/resources/pdfs/hello.pdf";

    public static final char[] PASSWORD = "password".toCharArray();

    public static final String[] RESULT_FILES = new String[] {
            "hello_signed_with_temp.pdf"
    };

    public void sign(String src, String temp, String dest, Certificate[] chain, PrivateKey pk,
            String digestAlgorithm, String provider, PdfSigner.CryptoStandard subfilter,
            String reason, String location)
            throws GeneralSecurityException, IOException {
        PdfReader reader = new PdfReader(src);

        // Pass the temporary file's path to the PdfSigner constructor
        PdfSigner signer = new PdfSigner(reader, new FileOutputStream(dest), temp, new StampingProperties());

        // Create the signature appearance
        Rectangle rect = new Rectangle(36, 648, 200, 100);
        PdfSignatureAppearance appearance = signer.getSignatureAppearance();
        appearance
                .setReason(reason)
                .setLocation(location)

                // Specify if the appearance before field is signed will be used
                // as a background for the signed field. The "false" value is the default value.
                .setReuseAppearance(false)
                .setPageRect(rect)
                .setPageNumber(1);
        signer.setFieldName("sig");

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

        new C2_02_SignHelloWorldWithTempFile().sign(SRC, DEST, DEST + RESULT_FILES[0], chain, pk,
                DigestAlgorithms.SHA256, provider.getName(), PdfSigner.CryptoStandard.CMS,
                "Temp test", "Ghent");
    }
}
