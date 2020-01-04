/*
    This file is part of the iText (R) project.
    Copyright (c) 1998-2020 iText Group NV
    Authors: iText Software.

    For more information, please contact iText Software at this address:
    sales@itextpdf.com
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
import com.itextpdf.kernel.pdf.StampingProperties;
import com.itextpdf.signatures.BouncyCastleDigest;
import com.itextpdf.signatures.DigestAlgorithms;
import com.itextpdf.signatures.IExternalDigest;
import com.itextpdf.signatures.IExternalSignature;
import com.itextpdf.signatures.PdfSignatureAppearance;
import com.itextpdf.signatures.PdfSigner;

import java.io.IOException;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.io.InputStream;
import java.io.File;
import java.io.ByteArrayOutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;

public class C4_07_ClientServerSigning {
    public static final String DEST = "./target/signatures/chapter04/";

    public static final String SRC = "./src/test/resources/pdfs/hello.pdf";
    public static final String CERT = "https://demo.itextsupport.com/SigningApp/itextpdf.cer";

    public static final String[] RESULT_FILES = new String[] {
            "hello_server.pdf"
    };

    public static void main(String[] args) throws GeneralSecurityException, IOException {
        File file = new File(DEST);
        file.mkdirs();

        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        URL certUrl = new URL(CERT);
        Certificate[] chain = new Certificate[1];
        try (InputStream stream = certUrl.openStream()) {
            chain[0] = factory.generateCertificate(stream);
        }

        new C4_07_ClientServerSigning().sign(SRC, DEST + RESULT_FILES[0], chain, PdfSigner.CryptoStandard.CMS,
                "Test", "Ghent");
    }

    public void sign(String src, String dest, Certificate[] chain, PdfSigner.CryptoStandard subfilter,
            String reason, String location) throws GeneralSecurityException, IOException {
        PdfReader reader = new PdfReader(src);
        PdfSigner signer = new PdfSigner(reader, new FileOutputStream(dest), new StampingProperties());

        // Create the signature appearance
        Rectangle rect = new Rectangle(36, 648, 200, 100);
        PdfSignatureAppearance appearance = signer.getSignatureAppearance();
        appearance
                .setReason(reason)
                .setLocation(location)
                .setPageRect(rect)
                .setPageNumber(1);
        signer.setFieldName("sig");

        IExternalDigest digest = new BouncyCastleDigest();
        IExternalSignature signature = new ServerSignature();

        // Sign the document using the detached mode, CMS or CAdES equivalent.
        signer.signDetached(digest, signature, chain, null, null, null,
                0, subfilter);
    }

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
                byte[] b = new byte[32];
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
}
