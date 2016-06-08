/*

    This file is part of the iText (R) project.
    Copyright (c) 1998-2016 iText Group NV

*/

/*
 * This class is part of the white paper entitled
 * "Digital Signatures for PDF documents"
 * written by Bruno Lowagie
 *
 * For more info, go to: http://itextpdf.com/learn
 */
package com.itextpdf.samples.signatures.chapter04;

import com.itextpdf.kernel.PdfException;
import com.itextpdf.kernel.geom.Rectangle;
import com.itextpdf.kernel.pdf.PdfReader;
import com.itextpdf.samples.SignatureTest;
import com.itextpdf.signatures.BouncyCastleDigest;
import com.itextpdf.signatures.DigestAlgorithms;
import com.itextpdf.signatures.IExternalDigest;
import com.itextpdf.signatures.IExternalSignature;
import com.itextpdf.signatures.PdfSignatureAppearance;
import com.itextpdf.signatures.PdfSigner;
import com.itextpdf.test.annotations.type.SampleTest;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;

import org.junit.Ignore;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import static org.junit.Assert.fail;

@Category(SampleTest.class)
public class C4_07_ClientServerSigning extends SignatureTest {
    public static final String SRC = "./src/test/resources/pdfs/hello.pdf";
    public static final String DEST = "./target/test/resources/signatures/chapter04/hello_server.pdf";
    public static final String CERT = "http://demo.itextsupport.com/SigningApp/itextpdf.cer";

    public class ServerSignature implements IExternalSignature {
        public static final String SIGN = "http://demo.itextsupport.com/SigningApp/signbytes";

        public String getHashAlgorithm() {
            return DigestAlgorithms.SHA256;
        }

        public String getEncryptionAlgorithm() {
            return "RSA";
        }

        public byte[] sign(byte[] message) throws GeneralSecurityException {
            try {
                URL url = new URL(SIGN);
                HttpURLConnection conn = (HttpURLConnection) url.openConnection();
                conn.setDoOutput(true);
                conn.setRequestMethod("POST");
                conn.connect();
                OutputStream os = conn.getOutputStream();
                os.write(message);
                os.flush();
                os.close();
                InputStream is = conn.getInputStream();
                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                byte[] b = new byte[1];
                int read;
                while ((read = is.read(b)) != -1) {
                    baos.write(b, 0, read);
                }
                is.close();
                return baos.toByteArray();
            } catch (IOException e) {
                throw new PdfException(e);
            }
        }
    }

    public void sign(String src, String dest,
                     Certificate[] chain,
                     PdfSigner.CryptoStandard subfilter,
                     String reason, String location)
            throws GeneralSecurityException, IOException {
        // Creating the reader and the signer
        PdfReader reader = new PdfReader(src);
        PdfSigner signer = new PdfSigner(reader, new FileOutputStream(dest), false);
        // Creating the appearance
        PdfSignatureAppearance appearance = signer.getSignatureAppearance()
                .setReason(reason)
                .setLocation(location)
                .setReuseAppearance(false);
        Rectangle rect = new Rectangle(36, 648, 200, 100);
        appearance
                .setPageRect(rect)
                .setPageNumber(1);
        signer.setFieldName("sig");
        // Creating the signature
        IExternalDigest digest = new BouncyCastleDigest();
        IExternalSignature signature = new ServerSignature();
        signer.signDetached(digest, signature, chain, null, null, null, 0, subfilter);
    }

    public static void main(String[] args) throws GeneralSecurityException, IOException {
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        URL certUrl = new URL(CERT);
        Certificate[] chain = new Certificate[1];
        chain[0] = factory.generateCertificate(certUrl.openStream());
        C4_07_ClientServerSigning app = new C4_07_ClientServerSigning();
        app.sign(SRC, DEST, chain, PdfSigner.CryptoStandard.CMS, "Test", "Ghent");
    }

    @Test
    public void runTest() throws IOException, InterruptedException, GeneralSecurityException {
        new File("./target/test/resources/signatures/chapter04/").mkdirs();
        C4_07_ClientServerSigning.main(null);

        String[] resultFiles = new String[]{"hello_server.pdf"};

        String destPath = String.format(outPath, "chapter04");
        String comparePath = String.format(cmpPath, "chapter04");

        String[] errors = new String[resultFiles.length];
        boolean error = false;

        HashMap<Integer, List<Rectangle>> ignoredAreas = new HashMap<Integer, List<Rectangle>>() {
            {
                put(1, Arrays.asList(new Rectangle(36, 648, 200, 100)));
            }
        };

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

    @Override
    protected void initKeyStoreForVerification(KeyStore ks) throws IOException, NoSuchAlgorithmException, CertificateException, KeyStoreException {
        super.initKeyStoreForVerification(ks);
        URL certUrl = new URL(CERT);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        Certificate itextCert = cf.generateCertificate(certUrl.openStream());
        ks.setCertificateEntry("itext", itextCert);
    }
}