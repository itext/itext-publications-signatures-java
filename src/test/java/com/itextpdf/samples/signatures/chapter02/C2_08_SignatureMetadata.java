package com.itextpdf.samples.signatures.chapter02;

import com.itextpdf.kernel.pdf.PdfName;
import com.itextpdf.kernel.pdf.PdfReader;
import com.itextpdf.kernel.pdf.PdfString;
import com.itextpdf.kernel.pdf.StampingProperties;
import com.itextpdf.signatures.BouncyCastleDigest;
import com.itextpdf.signatures.DigestAlgorithms;
import com.itextpdf.signatures.IExternalDigest;
import com.itextpdf.signatures.PdfSignature;
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

public class C2_08_SignatureMetadata {
    public static final String DEST = "./target/signatures/chapter02/";
    public static final String KEYSTORE = "./src/test/resources/encryption/certificate.p12";
    public static final String SRC = "./src/test/resources/pdfs/hello_to_sign.pdf";

    public static final char[] PASSWORD = "testpassphrase".toCharArray();

    public static final String[] RESULT_FILES = new String[] {
            "field_metadata.pdf"
    };

    public void sign(String src, String name, String dest, Certificate[] chain, PrivateKey pk,
            String digestAlgorithm, String provider, PdfSigner.CryptoStandard subfilter,
            String reason, String location, String contact, final String fullName)
            throws GeneralSecurityException, IOException {
        PdfReader reader = new PdfReader(src);
        PdfSigner signer = new PdfSigner(reader, new FileOutputStream(dest), new StampingProperties());

        // Create the signature appearance
        SignerProperties signerProps = new SignerProperties()
            .setReason(reason)
            .setLocation(location)
            .setContact(contact);

        // This name corresponds to the name of the field that already exists in the document.
        signerProps.setFieldName(name);

        signer.setSignerProperties(signerProps);

        // Set the signature event to allow modification of the signature dictionary.
        signer.setSignatureEvent(
                new PdfSigner.ISignatureEvent() {
                    @Override
                    public void getSignatureDictionary(PdfSignature sig) {
                        sig.put(PdfName.Name, new PdfString(fullName));
                    }
                }
        );

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

        C2_08_SignatureMetadata app = new C2_08_SignatureMetadata();
        app.sign(SRC, "Signature1", DEST + RESULT_FILES[0], chain, pk, DigestAlgorithms.SHA256,
                provider.getName(), PdfSigner.CryptoStandard.CMS, "Test metadata",
                "Ghent", "555 123 456", "Bruno L. Specimen");
    }
}
