/*

    This file is part of the iText (R) project.
    Copyright (c) 1998-2016 iText Group NV

*/

package com.itextpdf.samples.signatures.chapter04;

import com.itextpdf.kernel.geom.Rectangle;
import com.itextpdf.kernel.pdf.PdfDictionary;
import com.itextpdf.kernel.pdf.PdfName;
import com.itextpdf.kernel.pdf.PdfReader;
import com.itextpdf.samples.SignatureTest;
import com.itextpdf.signatures.BouncyCastleDigest;
import com.itextpdf.signatures.DigestAlgorithms;
import com.itextpdf.signatures.ExternalBlankSignatureContainer;
import com.itextpdf.signatures.IExternalSignatureContainer;
import com.itextpdf.signatures.PdfPKCS7;
import com.itextpdf.signatures.PdfSignatureAppearance;
import com.itextpdf.signatures.PdfSigner;
import com.itextpdf.signatures.PrivateKeySignature;
import com.itextpdf.test.annotations.type.SampleTest;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.util.Arrays;
import java.util.Calendar;
import java.util.HashMap;
import java.util.List;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import static org.junit.Assert.fail;

@Category(SampleTest.class)
public class C4_09_DeferredSigning extends SignatureTest {
    public static final String SRC = "./src/test/resources/pdfs/hello.pdf";
    public static final String TEMP = "./target/test/resources/signatures/chapter04/hello_empty_sig.pdf";
    public static final String KEYSTORE = "./src/test/resources/encryption/ks";
    public static final char[] PASSWORD = "password".toCharArray();
    public static final String DEST = "./target/test/resources/signatures/chapter04/hello_sig_ok.pdf";


    class MyExternalSignatureContainer implements IExternalSignatureContainer {

        protected PrivateKey pk;
        protected Certificate[] chain;

        public MyExternalSignatureContainer(PrivateKey pk, Certificate[] chain) {
            this.pk = pk;
            this.chain = chain;
        }

        public byte[] sign(InputStream is) throws GeneralSecurityException {
            try {
                PrivateKeySignature signature = new PrivateKeySignature(pk, "SHA256", "BC");
                String hashAlgorithm = signature.getHashAlgorithm();
                BouncyCastleDigest digest = new BouncyCastleDigest();
                PdfPKCS7 sgn = new PdfPKCS7(null, chain, hashAlgorithm, null, digest, false);
                byte hash[] = DigestAlgorithms.digest(is, digest.getMessageDigest(hashAlgorithm));
                Calendar cal = Calendar.getInstance();
                byte[] sh = sgn.getAuthenticatedAttributeBytes(hash, null, null, PdfSigner.CryptoStandard.CMS);
                byte[] extSignature = signature.sign(sh);
                sgn.setExternalDigest(extSignature, null, signature.getEncryptionAlgorithm());
                return sgn.getEncodedPKCS7(hash, null, null, null, PdfSigner.CryptoStandard.CMS);
            }
            catch (IOException ioe) {
                throw new RuntimeException(ioe);
            }
        }

        public void modifySigningDictionary(PdfDictionary signDic) {
        }
    }

    public void emptySignature(String src, String dest, String fieldname, Certificate[] chain) throws IOException, GeneralSecurityException {
        PdfReader reader = new PdfReader(src);
        PdfSigner signer = new PdfSigner(reader, new FileOutputStream(dest), false);
        PdfSignatureAppearance appearance = signer.getSignatureAppearance();
        appearance
                .setPageRect(new Rectangle(36, 748, 200, 100))
                .setPageNumber(1);
        signer.setFieldName(fieldname);
        appearance.setCertificate(chain[0]);
        IExternalSignatureContainer external = new ExternalBlankSignatureContainer(PdfName.Adobe_PPKLite, PdfName.Adbe_pkcs7_detached);
        signer.signExternalContainer(external, 8192);
    }

    public void createSignature(String src, String dest, String fieldname, PrivateKey pk, Certificate[] chain) throws IOException, GeneralSecurityException {
        PdfReader reader = new PdfReader(src);
        FileOutputStream os = new FileOutputStream(dest);
        PdfSigner signer = new PdfSigner(reader, os, false);
        IExternalSignatureContainer external = new MyExternalSignatureContainer(pk, chain);
        signer.signDeferred(signer.getDocument(), fieldname, os, external);
    }

    @Test
    public void runTest() throws IOException, InterruptedException, GeneralSecurityException {
        new File("./target/test/resources/signatures/chapter04/").mkdirs();
        C4_09_DeferredSigning.main(null);

        String[] resultFiles = new String[]{"hello_sig_ok.pdf"};

        String destPath = String.format(outPath, "chapter04");
        String comparePath = String.format(cmpPath, "chapter04");

        String[] errors = new String[resultFiles.length];
        boolean error = false;

        HashMap<Integer, List<Rectangle>> ignoredAreas = new HashMap<Integer, List<Rectangle>>() { {
            put(1, Arrays.asList(new Rectangle(36, 748, 200, 100)));
        }};

        for (int i = 0; i < resultFiles.length; i++) {
            String resultFile = resultFiles[i];
            String fileErrors = checkForErrors(destPath + resultFile, comparePath + "cmp_" + resultFile, destPath, ignoredAreas);
            if (fileErrors != null) {
                errors[i] = fileErrors;
                error = true;
            }
        }

        if (error) {
            fail(accumulateErrors(errors));
        }
    }

    public static void main(String[] args) throws IOException, GeneralSecurityException {
        BouncyCastleProvider providerBC = new BouncyCastleProvider();
        Security.addProvider(providerBC);
        // we load our private key from the key store
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        ks.load(new FileInputStream(KEYSTORE), PASSWORD);
        String alias = ks.aliases().nextElement();
        Certificate[] chain = ks.getCertificateChain(alias);
        PrivateKey pk = (PrivateKey) ks.getKey(alias, PASSWORD);

        C4_09_DeferredSigning app = new C4_09_DeferredSigning();
        app.emptySignature(SRC, TEMP, "sig", chain);
        app.createSignature(TEMP, DEST, "sig", pk, chain);
    }
}
