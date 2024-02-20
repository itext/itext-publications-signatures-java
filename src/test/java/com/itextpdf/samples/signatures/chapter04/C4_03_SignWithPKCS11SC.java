package com.itextpdf.samples.signatures.chapter04;

import java.io.File;
import java.io.FileOutputStream;
import java.util.Collection;
import sun.security.pkcs11.SunPKCS11;

import com.itextpdf.kernel.geom.Rectangle;
import com.itextpdf.kernel.pdf.PdfReader;
import com.itextpdf.kernel.pdf.StampingProperties;
import com.itextpdf.signatures.BouncyCastleDigest;
import com.itextpdf.signatures.ICrlClient;
import com.itextpdf.signatures.CrlClientOnline;
import com.itextpdf.signatures.DigestAlgorithms;
import com.itextpdf.signatures.IExternalDigest;
import com.itextpdf.signatures.IExternalSignature;
import com.itextpdf.signatures.IOcspClient;
import com.itextpdf.signatures.ITSAClient;
import com.itextpdf.signatures.OcspClientBouncyCastle;
import com.itextpdf.signatures.PdfSigner;
import com.itextpdf.signatures.PrivateKeySignature;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import sun.security.pkcs11.wrapper.CK_C_INITIALIZE_ARGS;
import sun.security.pkcs11.wrapper.CK_TOKEN_INFO;
import sun.security.pkcs11.wrapper.PKCS11;
import sun.security.pkcs11.wrapper.PKCS11Exception;

public class C4_03_SignWithPKCS11SC {
    public static final String DEST = "./target/signatures/chapter04/";

    public static final String SRC = "./src/test/resources/pdfs/hello.pdf";

    public static final String[] RESULT_FILES = new String[] {
            "hello_smartcard_Authentication.pdf",
            "hello_smartcard_Signature.pdf"
    };

    public static void main(String[] args) throws IOException, GeneralSecurityException {
        File file = new File(DEST);
        file.mkdirs();

        // Specify the correct path to the DLL.
        String dllPath = "c:/windows/system32/beidpkcs11.dll";
        long[] slots = getSlotsWithTokens(dllPath);
        if (slots != null) {
            String config = "name=beid\n" +
                    "library=" + dllPath + "\n" +
                    "slotListIndex = " + slots[0];
            ByteArrayInputStream bais = new ByteArrayInputStream(config.getBytes());
            Provider providerPKCS11 = new SunPKCS11(bais);
            Security.addProvider(providerPKCS11);
            BouncyCastleProvider providerBC = new BouncyCastleProvider();
            Security.addProvider(providerBC);
            KeyStore ks = KeyStore.getInstance("PKCS11");

            /* All the signing operations are passed to the BeId API.
             * That is why the stream and password are null.
             */
            ks.load(null, null);
            Enumeration<String> aliases = ks.aliases();
            while (aliases.hasMoreElements()) {
                System.out.println(aliases.nextElement());
            }

            smartCardSign(providerPKCS11.getName(), ks, "Authentication", DEST + RESULT_FILES[0]);
            smartCardSign(providerPKCS11.getName(), ks, "Signature", DEST + RESULT_FILES[1]);
        } else {
            System.out.println("An exception was encountered while getting token slot's indexes.");
        }
    }

    public static void smartCardSign(String provider, KeyStore ks, String alias, String dest)
            throws GeneralSecurityException, IOException {
        PrivateKey pk = (PrivateKey) ks.getKey(alias, null);
        Certificate[] chain = ks.getCertificateChain(alias);
        IOcspClient ocspClient = new OcspClientBouncyCastle(null);
        List<ICrlClient> crlList = new ArrayList<ICrlClient>();
        crlList.add(new CrlClientOnline(chain));

        new C4_03_SignWithPKCS11SC().sign(SRC, dest, chain, pk, DigestAlgorithms.SHA256, provider,
                PdfSigner.CryptoStandard.CMS, "Test", "Ghent",
                crlList, ocspClient, null, 0);
    }

    public void sign(String src, String dest, Certificate[] chain, PrivateKey pk,
            String digestAlgorithm, String provider, PdfSigner.CryptoStandard subfilter,
            String reason, String location, Collection<ICrlClient> crlList,
            IOcspClient ocspClient, ITSAClient tsaClient, int estimatedSize)
            throws GeneralSecurityException, IOException {
        PdfReader reader = new PdfReader(src);
        PdfSigner signer = new PdfSigner(reader, new FileOutputStream(dest), new StampingProperties());

        // Create the signature appearance
        Rectangle rect = new Rectangle(36, 648, 200, 100);
        signer
                .setReason(reason)
                .setLocation(location)
                .setPageRect(rect)
                .setPageNumber(1)
                .setFieldName("sig");

        IExternalSignature pks = new PrivateKeySignature(pk, digestAlgorithm, provider);
        IExternalDigest digest = new BouncyCastleDigest();

        // Sign the document using the detached mode, CMS or CAdES equivalent.
        signer.signDetached(digest, pks, chain, crlList, ocspClient, tsaClient, estimatedSize, subfilter);
    }

    // Method returns a list of token slot's indexes
    public static long[] getSlotsWithTokens(String libraryPath) {
        CK_C_INITIALIZE_ARGS initArgs = new CK_C_INITIALIZE_ARGS();
        String functionList = "C_GetFunctionList";

        initArgs.flags = 0;
        PKCS11 tmpPKCS11 = null;
        long[] slotList = null;
        try {
            try {
                tmpPKCS11 = PKCS11.getInstance(libraryPath, functionList, initArgs, false);
            } catch (IOException ex) {
                ex.printStackTrace();
                return null;
            }
        } catch (PKCS11Exception e) {
            try {
                initArgs = null;
                tmpPKCS11 = PKCS11.getInstance(libraryPath, functionList, initArgs, true);
            } catch (IOException | PKCS11Exception ex) {
                ex.printStackTrace();
                return null;
            }
        }

        try {
            slotList = tmpPKCS11.C_GetSlotList(true);

            for (long slot : slotList) {
                CK_TOKEN_INFO tokenInfo = tmpPKCS11.C_GetTokenInfo(slot);
                System.out.println("slot: " + slot + "\nmanufacturerID: "
                        + String.valueOf(tokenInfo.manufacturerID) + "\nmodel: "
                        + String.valueOf(tokenInfo.model));
            }
        } catch (Throwable ex) {
            ex.printStackTrace();
            return null;
        }

        return slotList;
    }
}
