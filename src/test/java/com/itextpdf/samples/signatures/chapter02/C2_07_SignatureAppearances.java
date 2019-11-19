/*
    This file is part of the iText (R) project.
    Copyright (c) 1998-2019 iText Group NV
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
package com.itextpdf.samples.signatures.chapter02;

import com.itextpdf.io.image.ImageData;
import com.itextpdf.io.image.ImageDataFactory;
import com.itextpdf.kernel.pdf.PdfReader;
import com.itextpdf.kernel.pdf.StampingProperties;
import com.itextpdf.signatures.BouncyCastleDigest;
import com.itextpdf.signatures.DigestAlgorithms;
import com.itextpdf.signatures.IExternalDigest;
import com.itextpdf.signatures.PdfSignatureAppearance;
import com.itextpdf.signatures.PdfSigner;
import com.itextpdf.signatures.PrivateKeySignature;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.util.Date;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class C2_07_SignatureAppearances {
    public static final String DEST = "./target/signatures/chapter02/";

    public static final String KEYSTORE = "./src/test/resources/encryption/ks";
    public static final String SRC = "./src/test/resources/pdfs/hello_to_sign.pdf";
    public static final String IMG = "./src/test/resources/img/1t3xt.gif";

    public static final char[] PASSWORD = "password".toCharArray();

    public static final String[] RESULT_FILES = new String[] {
            "signature_appearance_1.pdf",
            "signature_appearance_2.pdf",
            "signature_appearance_3.pdf",
            "signature_appearance_4.pdf"
    };

    public void sign(String src, String name, String dest, Certificate[] chain, PrivateKey pk, String digestAlgorithm,
            String provider, PdfSigner.CryptoStandard subfilter, String reason, String location,
            PdfSignatureAppearance.RenderingMode renderingMode, ImageData image)
            throws GeneralSecurityException, IOException {
        PdfReader reader = new PdfReader(src);
        PdfSigner signer = new PdfSigner(reader, new FileOutputStream(dest), new StampingProperties());

        // Create the signature appearance
        PdfSignatureAppearance appearance = signer.getSignatureAppearance();
        appearance.setReason(reason);
        appearance.setLocation(location);

        // This name corresponds to the name of the field that already exists in the document.
        signer.setFieldName(name);

        appearance.setLayer2Text("Signed on " + new Date().toString());

        // Set the rendering mode for this signature.
        appearance.setRenderingMode(renderingMode);

        // Set the Image object to render when the rendering mode is set to RenderingMode.GRAPHIC
        // or RenderingMode.GRAPHIC_AND_DESCRIPTION.
        appearance.setSignatureGraphic(image);

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
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        ks.load(new FileInputStream(KEYSTORE), PASSWORD);
        String alias = ks.aliases().nextElement();
        PrivateKey pk = (PrivateKey) ks.getKey(alias, PASSWORD);
        Certificate[] chain = ks.getCertificateChain(alias);
        ImageData image = ImageDataFactory.create(IMG);

        C2_07_SignatureAppearances app = new C2_07_SignatureAppearances();
        String signatureName = "Signature1";
        String location = "Ghent";
        app.sign(SRC, signatureName, DEST + RESULT_FILES[0], chain, pk,
                DigestAlgorithms.SHA256, provider.getName(), PdfSigner.CryptoStandard.CMS,
                "Appearance 1", location, PdfSignatureAppearance.RenderingMode.DESCRIPTION, null);

        app.sign(SRC, signatureName, DEST + RESULT_FILES[1], chain, pk,
                DigestAlgorithms.SHA256, provider.getName(), PdfSigner.CryptoStandard.CMS,
                "Appearance 2", location, PdfSignatureAppearance.RenderingMode.NAME_AND_DESCRIPTION, null);

        app.sign(SRC, signatureName, DEST + RESULT_FILES[2], chain, pk,
                DigestAlgorithms.SHA256, provider.getName(), PdfSigner.CryptoStandard.CMS,
                "Appearance 3", location, PdfSignatureAppearance.RenderingMode.GRAPHIC_AND_DESCRIPTION, image);

        app.sign(SRC, signatureName, DEST + RESULT_FILES[3], chain, pk,
                DigestAlgorithms.SHA256, provider.getName(), PdfSigner.CryptoStandard.CMS,
                "Appearance 4", location, PdfSignatureAppearance.RenderingMode.GRAPHIC, image);
    }
}
