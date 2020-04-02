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
package com.itextpdf.samples.signatures.chapter05;

import com.itextpdf.forms.PdfAcroForm;
import com.itextpdf.kernel.geom.Rectangle;
import com.itextpdf.kernel.pdf.PdfDictionary;
import com.itextpdf.kernel.pdf.PdfDocument;
import com.itextpdf.kernel.pdf.PdfName;
import com.itextpdf.kernel.pdf.PdfReader;
import com.itextpdf.kernel.pdf.PdfString;
import com.itextpdf.kernel.pdf.annot.PdfWidgetAnnotation;
import com.itextpdf.signatures.CertificateInfo;
import com.itextpdf.signatures.PdfPKCS7;
import com.itextpdf.signatures.SignaturePermissions;
import com.itextpdf.signatures.SignatureUtil;
import com.itextpdf.signatures.TimestampConstants;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.List;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.tsp.TimeStampToken;

public class C5_02_SignatureInfo {
    public static final String DEST = "./target/test/resources/signatures/chapter05/";

    public static final String EXAMPLE1 = "./src/test/resources/pdfs/step_4_signed_by_alice_bob_carol_and_dave.pdf";
    public static final String EXAMPLE2 = "./src/test/resources/pdfs/hello_signed4.pdf";
    public static final String EXAMPLE3 = "./src/test/resources/pdfs/field_metadata.pdf";

    public static final String EXPECTED_OUTPUT =
            "./src/test/resources/pdfs/step_4_signed_by_alice_bob_carol_and_dave.pdf\n" +
                    "===== sig1 =====\n" +
                    "Field on page 1; llx: 36.0, lly: 728.02, urx: 559.0; ury: 779.02\n" +
                    "Signature covers whole document: false\n" +
                    "Document revision: 1 of 4\n" +
                    "Integrity check OK? true\n" +
                    "Digest algorithm: SHA256\n" +
                    "Encryption algorithm: RSA\n" +
                    "Filter subtype: /adbe.pkcs7.detached\n" +
                    "Name of the signer: Alice Specimen\n" +
                    "Signed on: 2016-02-23\n" +
                    "Location: \n" +
                    "Reason: \n" +
                    "Contact info: \n" +
                    "Signature type: certification\n" +
                    "Filling out fields allowed: true\n" +
                    "Adding annotations allowed: false\n" +
                    "===== sig2 =====\n" +
                    "Field on page 1; llx: 36.0, lly: 629.04, urx: 559.0; ury: 680.04\n" +
                    "Signature covers whole document: false\n" +
                    "Document revision: 2 of 4\n" +
                    "Integrity check OK? true\n" +
                    "Digest algorithm: SHA256\n" +
                    "Encryption algorithm: RSA\n" +
                    "Filter subtype: /adbe.pkcs7.detached\n" +
                    "Name of the signer: Bob Specimen\n" +
                    "Signed on: 2016-02-23\n" +
                    "Location: \n" +
                    "Reason: \n" +
                    "Contact info: \n" +
                    "Signature type: approval\n" +
                    "Filling out fields allowed: true\n" +
                    "Adding annotations allowed: false\n" +
                    "Lock: /Include[sig1 approved_bob sig2 ]\n" +
                    "===== sig3 =====\n" +
                    "Field on page 1; llx: 36.0, lly: 530.05, urx: 559.0; ury: 581.05\n" +
                    "Signature covers whole document: false\n" +
                    "Document revision: 3 of 4\n" +
                    "Integrity check OK? true\n" +
                    "Digest algorithm: SHA256\n" +
                    "Encryption algorithm: RSA\n" +
                    "Filter subtype: /adbe.pkcs7.detached\n" +
                    "Name of the signer: Carol Specimen\n" +
                    "Signed on: 2016-02-23\n" +
                    "Location: \n" +
                    "Reason: \n" +
                    "Contact info: \n" +
                    "Signature type: approval\n" +
                    "Filling out fields allowed: true\n" +
                    "Adding annotations allowed: false\n" +
                    "Lock: /Include[sig1 approved_bob sig2 ]\n" +
                    "Lock: /Exclude[approved_dave sig4 ]\n" +
                    "===== sig4 =====\n" +
                    "Field on page 1; llx: 36.0, lly: 431.07, urx: 559.0; ury: 482.07\n" +
                    "Signature covers whole document: true\n" +
                    "Document revision: 4 of 4\n" +
                    "Integrity check OK? true\n" +
                    "Digest algorithm: SHA256\n" +
                    "Encryption algorithm: RSA\n" +
                    "Filter subtype: /adbe.pkcs7.detached\n" +
                    "Name of the signer: Dave Specimen\n" +
                    "Signed on: 2016-02-23\n" +
                    "Location: \n" +
                    "Reason: \n" +
                    "Contact info: \n" +
                    "Signature type: approval\n" +
                    "Filling out fields allowed: false\n" +
                    "Adding annotations allowed: false\n" +
                    "Lock: /Include[sig1 approved_bob sig2 ]\n" +
                    "Lock: /Exclude[approved_dave sig4 ]\n" +
                    "./src/test/resources/pdfs/hello_signed4.pdf\n" +
                    "===== sig =====\n" +
                    "Field on page 1; llx: 36.0, lly: 648.0, urx: 236.0; ury: 748.0\n" +
                    "Signature covers whole document: true\n" +
                    "Document revision: 1 of 1\n" +
                    "Integrity check OK? true\n" +
                    "Digest algorithm: RIPEMD160\n" +
                    "Encryption algorithm: RSA\n" +
                    "Filter subtype: /ETSI.CAdES.detached\n" +
                    "Name of the signer: Bruno Specimen\n" +
                    "Signed on: 2016-02-23\n" +
                    "Location: Ghent\n" +
                    "Reason: Test 4\n" +
                    "Contact info: \n" +
                    "Signature type: approval\n" +
                    "Filling out fields allowed: true\n" +
                    "Adding annotations allowed: true\n" +
                    "./src/test/resources/pdfs/field_metadata.pdf\n" +
                    "===== Signature1 =====\n" +
                    "Field on page 1; llx: 46.0674, lly: 472.172, urx: 332.563; ury: 726.831\n" +
                    "Signature covers whole document: true\n" +
                    "Document revision: 1 of 1\n" +
                    "Integrity check OK? true\n" +
                    "Digest algorithm: SHA256\n" +
                    "Encryption algorithm: RSA\n" +
                    "Filter subtype: /adbe.pkcs7.detached\n" +
                    "Name of the signer: Bruno Specimen\n" +
                    "Alternative name of the signer: Bruno L. Specimen\n" +
                    "Signed on: 2016-02-23\n" +
                    "Location: Ghent\n" +
                    "Reason: Test metadata\n" +
                    "Contact info: 555 123 456\n" +
                    "Signature type: approval\n" +
                    "Filling out fields allowed: true\n" +
                    "Adding annotations allowed: true\n";

    public SignaturePermissions inspectSignature(PdfDocument pdfDoc, SignatureUtil signUtil, PdfAcroForm form,
            String name, SignaturePermissions perms) throws GeneralSecurityException {
        List<PdfWidgetAnnotation> widgets = form.getField(name).getWidgets();

        // Check the visibility of the signature annotation
        if (widgets != null && widgets.size() > 0) {
            Rectangle pos = widgets.get(0).getRectangle().toRectangle();
            int pageNum = pdfDoc.getPageNumber(widgets.get(0).getPage());
            if (pos.getWidth() == 0 || pos.getHeight() == 0) {
                System.out.println("Invisible signature");
            } else {
                System.out.println(String.format("Field on page %s; llx: %s, lly: %s, urx: %s; ury: %s",
                        pageNum, pos.getLeft(), pos.getBottom(), pos.getRight(), pos.getTop()));
            }
        }

        /* Find out how the message digest of the PDF bytes was created,
         * how these bytes and additional attributes were signed
         * and how the signed bytes are stored in the PDF
         */
        PdfPKCS7 pkcs7 = verifySignature(signUtil, name);
        System.out.println("Digest algorithm: " + pkcs7.getHashAlgorithm());
        System.out.println("Encryption algorithm: " + pkcs7.getEncryptionAlgorithm());
        System.out.println("Filter subtype: " + pkcs7.getFilterSubtype());

        // Get the signing certificate to find out the name of the signer.
        X509Certificate cert = (X509Certificate) pkcs7.getSigningCertificate();
        System.out.println("Name of the signer: " + CertificateInfo.getSubjectFields(cert).getField("CN"));
        if (pkcs7.getSignName() != null) {
            System.out.println("Alternative name of the signer: " + pkcs7.getSignName());
        }

        // Get the signing time
        SimpleDateFormat date_format = new SimpleDateFormat("yyyy-MM-dd");

        /* Mind that the getSignDate() method is not that secure as timestamp
         * because it's based only on signature author claim. I.e. this value can only be trusted
         * if signature is trusted and it cannot be used for signature verification.
         */
        System.out.println("Signed on: " + date_format.format(pkcs7.getSignDate().getTime()));

        /* If a timestamp was applied, retrieve information about it.
         * Timestamp is a secure source of signature creation time,
         * because it's based on Time Stamping Authority service.
         */
        if (TimestampConstants.UNDEFINED_TIMESTAMP_DATE != pkcs7.getTimeStampDate()) {
            System.out.println("TimeStamp: " + date_format.format(pkcs7.getTimeStampDate().getTime()));
            TimeStampToken ts = pkcs7.getTimeStampToken();
            System.out.println("TimeStamp service: " + ts.getTimeStampInfo().getTsa());
            System.out.println("Timestamp verified? " + pkcs7.verifyTimestampImprint());
        }

        System.out.println("Location: " + pkcs7.getLocation());
        System.out.println("Reason: " + pkcs7.getReason());

        /* If you want less common entries than PdfPKCS7 object has, such as the contact info,
         * you should use the signature dictionary and get the properties by name.
         */
        PdfDictionary sigDict = signUtil.getSignatureDictionary(name);
        PdfString contact = sigDict.getAsString(PdfName.ContactInfo);
        if (contact != null) {
            System.out.println("Contact info: " + contact);
        }

        /* Every new signature can add more restrictions to a document, but it can't take away previous restrictions.
         * So if you want to retrieve information about signatures restrictions, you need to pass
         * the SignaturePermissions instance of the previous signature, or null if there was none.
         */
        perms = new SignaturePermissions(sigDict, perms);
        System.out.println("Signature type: " + (perms.isCertification() ? "certification" : "approval"));
        System.out.println("Filling out fields allowed: " + perms.isFillInAllowed());
        System.out.println("Adding annotations allowed: " + perms.isAnnotationsAllowed());
        for (SignaturePermissions.FieldLock lock : perms.getFieldLocks()) {
            System.out.println("Lock: " + lock.toString());
        }

        return perms;
    }

    public PdfPKCS7 verifySignature(SignatureUtil signUtil, String name) throws GeneralSecurityException {
        PdfPKCS7 pkcs7 = signUtil.readSignatureData(name);

        System.out.println("Signature covers whole document: " + signUtil.signatureCoversWholeDocument(name));
        System.out.println("Document revision: " + signUtil.getRevision(name) + " of " + signUtil.getTotalRevisions());
        System.out.println("Integrity check OK? " + pkcs7.verifySignatureIntegrityAndAuthenticity());

        return pkcs7;
    }

    public void inspectSignatures(String path) throws IOException, GeneralSecurityException {
        PdfDocument pdfDoc = new PdfDocument(new PdfReader(path));
        PdfAcroForm form = PdfAcroForm.getAcroForm(pdfDoc, false);
        SignaturePermissions perms = null;
        SignatureUtil signUtil = new SignatureUtil(pdfDoc);
        List<String> names = signUtil.getSignatureNames();

        System.out.println(path);
        for (String name : names) {
            System.out.println("===== " + name + " =====");
            perms = inspectSignature(pdfDoc, signUtil, form, name, perms);
        }
    }

    public static void main(String[] args) throws IOException, GeneralSecurityException {
        BouncyCastleProvider provider = new BouncyCastleProvider();
        Security.addProvider(provider);

        C5_02_SignatureInfo app = new C5_02_SignatureInfo();
        app.inspectSignatures(EXAMPLE1);
        app.inspectSignatures(EXAMPLE2);
        app.inspectSignatures(EXAMPLE3);
    }
}
