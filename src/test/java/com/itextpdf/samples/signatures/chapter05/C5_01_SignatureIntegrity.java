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
package com.itextpdf.samples.signatures.chapter05;

import com.itextpdf.kernel.pdf.PdfDocument;
import com.itextpdf.kernel.pdf.PdfReader;
import com.itextpdf.samples.SignatureTest;
import com.itextpdf.signatures.PdfPKCS7;
import com.itextpdf.signatures.SignatureUtil;
import com.itextpdf.test.annotations.type.SampleTest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Assert;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.experimental.categories.Category;

import javax.smartcardio.CardException;
import java.io.File;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Security;
import java.util.List;

@Category(SampleTest.class)
public class C5_01_SignatureIntegrity extends SignatureTest {
    public static final String EXAMPLE1 = "./src/test/resources/pdfs/hello_level_1_annotated.pdf";
    public static final String EXAMPLE2 = "./src/test/resources/pdfs/step_4_signed_by_alice_bob_carol_and_dave.pdf";
    public static final String EXAMPLE3 = "./src/test/resources/pdfs/step_6_signed_by_dave_broken_by_chuck.pdf";

    public static final String expectedOutput =
            "===== sig =====\n" +
            "Signature covers whole document: false\n" +
            "Document revision: 1 of 2\n" +
            "Integrity check OK? true\n" +
            "\n" +
            "===== sig1 =====\n" +
            "Signature covers whole document: false\n" +
            "Document revision: 1 of 4\n" +
            "Integrity check OK? true\n" +
            "===== sig2 =====\n" +
            "Signature covers whole document: false\n" +
            "Document revision: 2 of 4\n" +
            "Integrity check OK? true\n" +
            "===== sig3 =====\n" +
            "Signature covers whole document: false\n" +
            "Document revision: 3 of 4\n" +
            "Integrity check OK? true\n" +
            "===== sig4 =====\n" +
            "Signature covers whole document: true\n" +
            "Document revision: 4 of 4\n" +
            "Integrity check OK? true\n" +
            "\n" +
            "===== sig1 =====\n" +
            "Signature covers whole document: false\n" +
            "Document revision: 1 of 5\n" +
            "Integrity check OK? true\n" +
            "===== sig2 =====\n" +
            "Signature covers whole document: false\n" +
            "Document revision: 2 of 5\n" +
            "Integrity check OK? true\n" +
            "===== sig3 =====\n" +
            "Signature covers whole document: false\n" +
            "Document revision: 3 of 5\n" +
            "Integrity check OK? true\n" +
            "===== sig4 =====\n" +
            "Signature covers whole document: false\n" +
            "Document revision: 4 of 5\n" +
            "Integrity check OK? true\n" +
            "\n";

    public PdfPKCS7 verifySignature(SignatureUtil signUtil, String name) throws GeneralSecurityException, IOException {
        System.out.println("Signature covers whole document: " + signUtil.signatureCoversWholeDocument(name));
        System.out.println("Document revision: " + signUtil.getRevision(name) + " of " + signUtil.getTotalRevisions());
        PdfPKCS7 pkcs7 = signUtil.verifySignature(name);
        System.out.println("Integrity check OK? " + pkcs7.verify());
        return pkcs7;
    }

    public void verifySignatures(String path) throws IOException, GeneralSecurityException {
        // System.out.println(path);
        PdfDocument pdfDoc = new PdfDocument(new PdfReader(path));
        SignatureUtil signUtil = new SignatureUtil(pdfDoc);
        List<String> names = signUtil.getSignatureNames();
        for (String name : names) {
            System.out.println("===== " + name + " =====");
            verifySignature(signUtil, name);
        }
        System.out.println();
    }

    public static void main(String[] args) throws IOException, GeneralSecurityException {
        BouncyCastleProvider provider = new BouncyCastleProvider();
        Security.addProvider(provider);
        C5_01_SignatureIntegrity app = new C5_01_SignatureIntegrity();
        app.verifySignatures(EXAMPLE1);
        app.verifySignatures(EXAMPLE2);
        app.verifySignatures(EXAMPLE3);
    }

    @Test
    public void runTest() throws GeneralSecurityException, IOException, InterruptedException, CardException {
        new File("./target/test/resources/signatures/chapter05/").mkdirs();
        setupSystemOutput();
        C5_01_SignatureIntegrity.main(null);
        String sysOut = getSystemOutput();

        Assert.assertEquals("Unexpected output", expectedOutput, sysOut);
    }
}
