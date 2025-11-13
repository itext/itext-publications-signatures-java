package com.itextpdf.samples.signatures.chapter05;

import com.itextpdf.kernel.pdf.PdfDocument;
import com.itextpdf.kernel.pdf.PdfReader;
import com.itextpdf.signatures.IssuingCertificateRetriever;
import com.itextpdf.signatures.validation.SignatureValidationProperties;
import com.itextpdf.signatures.validation.SignatureValidator;
import com.itextpdf.signatures.validation.ValidatorChainBuilder;
import com.itextpdf.signatures.validation.report.ValidationReport;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.security.GeneralSecurityException;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.Collections;

public class C5_03_CertificateValidation {
    public static final String DEST = "./target/test/resources/signatures/chapter05/";

    public static final String ROOT = "./src/test/resources/encryption/rootRsa.cer";

    public static final String EXAMPLE = "./src/test/resources/pdfs/signedPAdES-LT.pdf";

    public static final String EXPECTED_OUTPUT = "./src/test/resources/pdfs/signedPAdES-LT.pdf\n"
            + "ValidationReport{validationResult=INDETERMINATE\n"
            + "reportItems=\n"
            + "ReportItem{checkName='Signature verification check.', message='Validating signature Signature1', "
            + "cause=null, status=INFO}, \n"
            + "CertificateReportItem{baseclass=\n"
            + "ReportItem{checkName='CRL response check.', message='CRL response is not fresh enough: this update: "
            + "2017-04-10 12:48, validation date: 2025-11-12 17:32, freshness: PT720H.', cause=null, status=INFO}\n"
            + "certificate=CN=iTextTestTsCert, OU=test, O=iText, L=Minsk, C=BY}, \n"
            + "CertificateReportItem{baseclass=\n"
            + "ReportItem{checkName='Revocation data check.', message='Certificate revocation status cannot be "
            + "checked: no revocation data available or the status cannot be determined.', cause=null, "
            + "status=INDETERMINATE}\n"
            + "certificate=CN=iTextTestTsCert, OU=test, O=iText, L=Minsk, C=BY}, \n"
            + "CertificateReportItem{baseclass=\n"
            + "ReportItem{checkName='Certificate check.', message='Certificate CN=iTextTestRoot, OU=test, O=iText, "
            + "L=Minsk, C=BY is trusted, revocation data checks are not required.', cause=null, status=INFO}\n"
            + "certificate=CN=iTextTestRoot, OU=test, O=iText, L=Minsk, C=BY}, \n"
            + "CertificateReportItem{baseclass=\n"
            + "ReportItem{checkName='Certificate check.', message='Trusted Certificate is taken from manually "
            + "configured Trust List.', cause=null, status=INFO}\n"
            + "certificate=CN=iTextTestRoot, OU=test, O=iText, L=Minsk, C=BY}, \n"
            + "CertificateReportItem{baseclass=\n"
            + "ReportItem{checkName='OCSP response check.', message='OCSP response is not fresh enough: this update: "
            + "2017-04-10 12:48, validation date: 2025-11-12 17:32, freshness: PT720H.', cause=null, status=INFO}\n"
            + "certificate=CN=iTextTestRsaCert01, OU=test, O=iText, L=Minsk, C=BY}, \n"
            + "CertificateReportItem{baseclass=\n"
            + "ReportItem{checkName='CRL response check.', message='CRL response is not fresh enough: this update: "
            + "2017-04-10 12:48, validation date: 2025-11-12 17:32, freshness: PT720H.', cause=null, status=INFO}\n"
            + "certificate=CN=iTextTestRsaCert01, OU=test, O=iText, L=Minsk, C=BY}, \n"
            + "CertificateReportItem{baseclass=\n"
            + "ReportItem{checkName='Revocation data check.', message='Certificate revocation status cannot be "
            + "checked: no revocation data available or the status cannot be determined.', cause=null, "
            + "status=INDETERMINATE}\n"
            + "certificate=CN=iTextTestRsaCert01, OU=test, O=iText, L=Minsk, C=BY}, \n"
            + "CertificateReportItem{baseclass=\n"
            + "ReportItem{checkName='Certificate check.', message='Certificate CN=iTextTestRoot, OU=test, O=iText, "
            + "L=Minsk, C=BY is trusted, revocation data checks are not required.', cause=null, status=INFO}\n"
            + "certificate=CN=iTextTestRoot, OU=test, O=iText, L=Minsk, C=BY}, \n"
            + "CertificateReportItem{baseclass=\n"
            + "ReportItem{checkName='Certificate check.', message='Trusted Certificate is taken from manually "
            + "configured Trust List.', cause=null, status=INFO}\n"
            + "certificate=CN=iTextTestRoot, OU=test, O=iText, L=Minsk, C=BY}, }";

    public static final String STRING_TO_IGNORE = "freshness: PT720H.";

    private static PrintStream OUT_STREAM = System.out;

    public void verifySignatures(String path) throws IOException, GeneralSecurityException {
        // Set up the validator.
        SignatureValidationProperties properties = new SignatureValidationProperties();

        IssuingCertificateRetriever certificateRetriever = new IssuingCertificateRetriever();
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        Certificate rootCert = cf.generateCertificate(new FileInputStream(ROOT));
        certificateRetriever.addTrustedCertificates(Collections.singleton(rootCert));

        ValidatorChainBuilder validatorChainBuilder = new ValidatorChainBuilder()
                .withIssuingCertificateRetrieverFactory(() -> certificateRetriever)
                .withSignatureValidationProperties(properties);

        ValidationReport report;
        try (PdfDocument document = new PdfDocument(new PdfReader(path))) {
            OUT_STREAM.println(path);
            SignatureValidator validator = validatorChainBuilder.buildSignatureValidator(document);

            // Validate all signatures in the document.
            report = validator.validateSignatures();
            OUT_STREAM.println(report);
        }
    }

    public static void main(String[] args) throws IOException, GeneralSecurityException {
        BouncyCastleProvider provider = new BouncyCastleProvider();
        Security.addProvider(provider);
        C5_03_CertificateValidation app = new C5_03_CertificateValidation();

        app.verifySignatures(EXAMPLE);
    }
}
