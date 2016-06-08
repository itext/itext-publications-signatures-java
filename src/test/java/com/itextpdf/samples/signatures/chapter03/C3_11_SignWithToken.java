///*
//
//    This file is part of the iText (R) project.
//    Copyright (c) 1998-2016 iText Group NV
//
//*/
//
///*
//* This class is part of the white paper entitled
//* "Digital Signatures for PDF documents"
//* written by Bruno Lowagie
//*
//* For more info, go to: http://itextpdf.com/learn
//*/
//package com.itextpdf.samples.signatures.chapter03;
//
//import sun.security.mscapi.SunMSCAPI;
//import com.itextpdf.signatures.CertificateUtil;
//import com.itextpdf.signatures.CrlClient;
//import com.itextpdf.signatures.CrlClientOnline;
//import com.itextpdf.signatures.DigestAlgorithms;
//import com.itextpdf.signatures.OcspClient;
//import com.itextpdf.signatures.OcspClientBouncyCastle;
//import com.itextpdf.signatures.PdfSigner;
//import com.itextpdf.signatures.TSAClient;
//import com.itextpdf.signatures.TSAClientBouncyCastle;
//
//import java.io.File;
//import java.io.IOException;
//import java.security.GeneralSecurityException;
//import java.security.KeyStore;
//import java.security.PrivateKey;
//import java.security.Security;
//import java.security.cert.Certificate;
//import java.security.cert.X509Certificate;
//import java.util.ArrayList;
//import java.util.List;
//
//import org.bouncycastle.jce.provider.BouncyCastleProvider;
//import org.junit.Ignore;
//import org.junit.Test;
//import static org.junit.Assert.fail;
//
//@Ignore("Put property file with valid data")
//public class C3_11_SignWithToken extends C3_01_SignWithCAcert {
//    public static final String SRC = "./src/test/resources/pdfs/hello.pdf";
//    public static final String DEST = "./target/test/resources/signatures/chapter03/hello_token.pdf";
//
//    public static void main(String[] args) throws IOException, GeneralSecurityException {
//        BouncyCastleProvider providerBC = new BouncyCastleProvider();
//        Security.addProvider(providerBC);
//        SunMSCAPI providerMSCAPI = new SunMSCAPI();
//        Security.addProvider(providerMSCAPI);
//        KeyStore ks = KeyStore.getInstance("Windows-MY");
//        ks.load(null, null);
//        String alias = "Bruno Lowagie";
//        PrivateKey pk = (PrivateKey) ks.getKey(alias, null);
//        Certificate[] chain = ks.getCertificateChain(alias);
//        OcspClient ocspClient = new OcspClientBouncyCastle();
//        TSAClient tsaClient = null;
//        for (int i = 0; i < chain.length; i++) {
//            X509Certificate cert = (X509Certificate) chain[i];
//            String tsaUrl = CertificateUtil.getTSAURL(cert);
//            if (tsaUrl != null) {
//                tsaClient = new TSAClientBouncyCastle(tsaUrl);
//                break;
//            }
//        }
//        List<CrlClient> crlList = new ArrayList<CrlClient>();
//        crlList.add(new CrlClientOnline(chain));
//        C3_11_SignWithToken app = new C3_11_SignWithToken();
//        app.sign(SRC, DEST, chain, pk, DigestAlgorithms.SHA384, providerMSCAPI.getName(), PdfSigner.CryptoStandard.CMS, "Test", "Ghent",
//                crlList, ocspClient, tsaClient, 0);
//    }
//
//    @Test
//    public void runTest() throws IOException, InterruptedException, GeneralSecurityException {
//        new File("./target/test/resources/signatures/chapter03/").mkdirs();
//        C3_11_SignWithToken.main(null);
//
//        String[] resultFiles = new String[]{"hello_token.pdf"};
//
//        String destPath = String.format(outPath, "chapter03");
//        String comparePath = String.format(cmpPath, "chapter03");
//
//        String[] errors = new String[resultFiles.length];
//        boolean error = false;
//
////        HashMap<Integer, List<Rectangle>> ignoredAreas = new HashMap<Integer, List<Rectangle>>() { {
////            put(1, Arrays.asList(new Rectangle(36, 648, 200, 100)));
////        }};
//
//        for (int i = 0; i < resultFiles.length; i++) {
//            String resultFile = resultFiles[i];
//            String fileErrors = checkForErrors(destPath + resultFile, comparePath + "cmp_" + resultFile, destPath, /*ignoredAreas*/ null);
//            if (fileErrors != null) {
//                errors[i] = fileErrors;
//                error = true;
//            }
//        }
//
//        if (error) {
//            fail(accumulateErrors(errors));
//        }
//    }
//}
