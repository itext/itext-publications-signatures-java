/*
    This file is part of the iText (R) project.
    Copyright (c) 1998-2022 iText Group NV
    Authors: iText Software.

    For more information, please contact iText Software at this address:
    sales@itextpdf.com
 */
package com.itextpdf.samples.signatures.chapter05;

import com.itextpdf.bouncycastle.cert.ocsp.BasicOCSPRespBC;
import com.itextpdf.commons.bouncycastle.cert.ocsp.IBasicOCSPResp;
import com.itextpdf.kernel.pdf.PdfDocument;
import com.itextpdf.kernel.pdf.PdfReader;
import com.itextpdf.signatures.CRLVerifier;
import com.itextpdf.signatures.CertificateVerification;
import com.itextpdf.signatures.OCSPVerifier;
import com.itextpdf.signatures.PdfPKCS7;
import com.itextpdf.signatures.SignatureUtil;
import com.itextpdf.signatures.TimestampConstants;
import com.itextpdf.signatures.VerificationException;
import com.itextpdf.signatures.VerificationOK;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.AppenderBase;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.CRL;
import java.security.cert.Certificate;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.List;
import java.util.TimeZone;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.LoggerFactory;

public class C5_03_CertificateValidation {
    public static final String DEST = "./target/test/resources/signatures/chapter05/";

    public static final String ROOT = "./src/test/resources/encryption/rootRsa.cer";

    public static final String EXAMPLE = "./src/test/resources/pdfs/signedPAdES-LT.pdf";

    public static final String EXPECTED_OUTPUT = "./src/test/resources/pdfs/signedPAdES-LT.pdf\n"
            + "===== Signature1 =====\n"
            + "Signature covers whole document: false\n"
            + "Document revision: 1 of 2\n"
            + "Integrity check OK? true\n"
            + "Certificates verified against the KeyStore\n"
            + "=== Certificate 0 ===\n"
            + "Issuer: CN=iTextTestRoot, OU=test, O=iText, L=Minsk, C=BY\n"
            + "Subject: CN=iTextTestRsaCert01, OU=test, O=iText, L=Minsk, C=BY\n"
            + "Valid from: 2017-04-07-15-33\n"
            + "Valid to: 2117-04-07-15-33\n"
            + "The certificate was valid at the time of signing.\n"
            + "The certificate is still valid.\n"
            + "=== Certificate 1 ===\n"
            + "Issuer: CN=iTextTestRoot, OU=test, O=iText, L=Minsk, C=BY\n"
            + "Subject: CN=iTextTestRoot, OU=test, O=iText, L=Minsk, C=BY\n"
            + "Valid from: 2017-04-07-13-20\n"
            + "Valid to: 2117-04-07-13-20\n"
            + "The certificate was valid at the time of signing.\n"
            + "The certificate is still valid.\n"
            + "=== Checking validity of the document at the time of signing ===\n"
            + "com.itextpdf.signatures.OCSPVerifier INFO Valid OCSPs found: 0\n"
            + "com.itextpdf.signatures.CRLVerifier INFO Valid CRLs found: 0\n"
            + "The signing certificate couldn't be verified\n"
            + "=== Checking validity of the document today ===\n"
            + "com.itextpdf.signatures.OCSPVerifier INFO Valid OCSPs found: 0\n"
            + "com.itextpdf.signatures.CRLVerifier INFO Valid CRLs found: 0\n"
            + "The signing certificate couldn't be verified"
            +"\n";

    private static PrintStream OUT_STREAM = System.out;
    private static AppenderBase<ILoggingEvent> appender;
    private KeyStore ks;

    public void verifySignatures(String path) throws IOException, GeneralSecurityException {
        PdfDocument pdfDoc = new PdfDocument(new PdfReader(path));
        SignatureUtil signUtil = new SignatureUtil(pdfDoc);
        List<String> names = signUtil.getSignatureNames();

        OUT_STREAM.println(path);
        for (String name : names) {
            OUT_STREAM.println("===== " + name + " =====");
            verifySignature(signUtil, name);
        }
    }

    public PdfPKCS7 verifySignature(SignatureUtil signUtil, String name) throws GeneralSecurityException,
            IOException {
        PdfPKCS7 pkcs7 = getSignatureData(signUtil, name);
        Certificate[] certs = pkcs7.getSignCertificateChain();

        // Timestamp is a secure source of signature creation time,
        // because it's based on Time Stamping Authority service.
        Calendar cal = pkcs7.getTimeStampDate();

        // If there is no timestamp, use the current date
        if (TimestampConstants.UNDEFINED_TIMESTAMP_DATE == cal) {
            cal = Calendar.getInstance();
        }

        // Check if the certificate chain, presented in the PDF, can be verified against
        // the created key store.
        List<VerificationException> errors = CertificateVerification.verifyCertificates(certs, ks, cal);
        if (errors.size() == 0) {
            OUT_STREAM.println("Certificates verified against the KeyStore");
        } else {
            OUT_STREAM.println(errors);
        }

        // Find out if certificates were valid on the signing date, and if they are still valid today
        for (int i = 0; i < certs.length; i++) {
            X509Certificate cert = (X509Certificate) certs[i];
            OUT_STREAM.println("=== Certificate " + i + " ===");
            showCertificateInfo(cert, cal.getTime());
        }

        // Take the signing certificate
        X509Certificate signCert = (X509Certificate) certs[0];

        // Take the certificate of the issuer of that certificate (or null if it was self-signed).
        X509Certificate issuerCert = (certs.length > 1 ? (X509Certificate) certs[1] : null);

        OUT_STREAM.println("=== Checking validity of the document at the time of signing ===");
        checkRevocation(pkcs7, signCert, issuerCert, cal.getTime());

        OUT_STREAM.println("=== Checking validity of the document today ===");
        checkRevocation(pkcs7, signCert, issuerCert, new Date());

        return pkcs7;
    }

    public PdfPKCS7 getSignatureData(SignatureUtil signUtil, String name) throws GeneralSecurityException {
        PdfPKCS7 pkcs7 = signUtil.readSignatureData(name);

        OUT_STREAM.println("Signature covers whole document: " + signUtil.signatureCoversWholeDocument(name));
        OUT_STREAM.println("Document revision: " + signUtil.getRevision(name) + " of " + signUtil.getTotalRevisions());
        OUT_STREAM.println("Integrity check OK? " + pkcs7.verifySignatureIntegrityAndAuthenticity());

        return pkcs7;
    }

    public void showCertificateInfo(X509Certificate cert, Date signDate) {
        OUT_STREAM.println("Issuer: " + cert.getIssuerDN());
        OUT_STREAM.println("Subject: " + cert.getSubjectDN());
        SimpleDateFormat date_format = new SimpleDateFormat("yyyy-MM-dd-HH-mm");
        date_format.setTimeZone(TimeZone.getTimeZone("Universal"));
        OUT_STREAM.println("Valid from: " + date_format.format(cert.getNotBefore()));
        OUT_STREAM.println("Valid to: " + date_format.format(cert.getNotAfter()));

        // Check if a certificate was valid on the signing date
        try {
            cert.checkValidity(signDate);
            OUT_STREAM.println("The certificate was valid at the time of signing.");
        } catch (CertificateExpiredException e) {
            OUT_STREAM.println("The certificate was expired at the time of signing.");
        } catch (CertificateNotYetValidException e) {
            OUT_STREAM.println("The certificate wasn't valid yet at the time of signing.");
        }

        // Check if a certificate is still valid now
        try {
            cert.checkValidity();
            OUT_STREAM.println("The certificate is still valid.");
        } catch (CertificateExpiredException e) {
            OUT_STREAM.println("The certificate has expired.");
        } catch (CertificateNotYetValidException e) {
            OUT_STREAM.println("The certificate isn't valid yet.");
        }
    }

    public static void checkRevocation(PdfPKCS7 pkcs7, X509Certificate signCert, X509Certificate issuerCert, Date date)
            throws GeneralSecurityException, IOException {
        List<IBasicOCSPResp> ocsps = new ArrayList<>();
        if (pkcs7.getOcsp() != null) {
            ocsps.add(new BasicOCSPRespBC(((BasicOCSPRespBC) pkcs7.getOcsp()).getBasicOCSPResp()));
        }

        // Check if the OCSP responses in the list were valid for the certificate on a specific date.
        OCSPVerifier ocspVerifier = new OCSPVerifier(null, ocsps);
        List<VerificationOK> verification = ocspVerifier.verify(signCert, issuerCert, date);

        // If that list is empty, we can't verify using OCSP, and we need to look for CRLs.
        if (verification.size() == 0) {
            List<X509CRL> crls = new ArrayList<X509CRL>();
            if (pkcs7.getCRLs() != null) {
                for (CRL crl : pkcs7.getCRLs()) {
                    crls.add((X509CRL) crl);
                }
            }

            // Check if the CRLs in the list were valid on a specific date.
            CRLVerifier crlVerifier = new CRLVerifier(null, crls);
            verification.addAll(crlVerifier.verify(signCert, issuerCert, date));
        }

        if (verification.size() == 0) {
            OUT_STREAM.println("The signing certificate couldn't be verified");
        } else {
            for (VerificationOK v : verification) {
                OUT_STREAM.println(v);
            }
        }
    }

    public static void main(String[] args) throws IOException, GeneralSecurityException {
        BouncyCastleProvider provider = new BouncyCastleProvider();
        Security.addProvider(provider);
        C5_03_CertificateValidation app = new C5_03_CertificateValidation();

        Logger ocspLogger = (Logger) LoggerFactory.getLogger(OCSPVerifier.class);
        Logger clrLogger = (Logger) LoggerFactory.getLogger(CRLVerifier.class);

        /* Add a custom appender to the specified logger.
         * Mind that if you have any added console appenders, then log messages in the console
         * could be shown multiple times.
         */
        setUpLogger(ocspLogger);
        setUpLogger(clrLogger);

        // Create your own root certificate store and add certificates
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        ks.load(null, null);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        try (FileInputStream stream = new FileInputStream(ROOT)) {
            ks.setCertificateEntry("root", cf.generateCertificate(stream));
        }

        app.setKeyStore(ks);

        app.verifySignatures(EXAMPLE);

        // Detach the custom appender from the logger.
        resetLogger(ocspLogger);
        resetLogger(clrLogger);
    }

    private void setKeyStore(KeyStore ks) {
        this.ks = ks;
    }

    private static void setUpLogger(Logger logger) {
        appender = new CustomListAppender<ILoggingEvent>(OUT_STREAM);
        appender.setName("customAppender");
        appender.start();
        logger.addAppender(appender);
    }

    private static void resetLogger(Logger logger) {
        appender.stop();
        logger.detachAppender(appender);

    }

    // Custom log appender to write log messages to the specific print stream
    private static class CustomListAppender<E> extends AppenderBase<E> {
        private PrintStream stream;

        public CustomListAppender(PrintStream stream) {
            this.stream = stream;
        }

        @Override
        protected void append(E e) {
            ILoggingEvent event = (ILoggingEvent) e;
            stream.println(event.getLoggerName() + " " + event.getLevel() + " " + event.getMessage());
        }
    }
}
