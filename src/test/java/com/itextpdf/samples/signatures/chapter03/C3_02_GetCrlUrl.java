package com.itextpdf.samples.signatures.chapter03;

import com.itextpdf.signatures.CertificateUtil;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Properties;

public class C3_02_GetCrlUrl {
    public static void main(String[] args) throws IOException, GeneralSecurityException {
        Properties properties = new Properties();

        // Specify the correct path to the certificate
        properties.load(new FileInputStream("c:/home/blowagie/key.properties"));
        String path = properties.getProperty("PRIVATE");
        char[] pass = properties.getProperty("PASSWORD").toCharArray();

        BouncyCastleProvider provider = new BouncyCastleProvider();
        Security.addProvider(provider);
        KeyStore ks = KeyStore.getInstance("pkcs12", provider.getName());
        ks.load(new FileInputStream(path), pass);
        String alias = ks.aliases().nextElement();
        Certificate[] chain = ks.getCertificateChain(alias);

        for (int i = 0; i < chain.length; i++) {
            X509Certificate cert = (X509Certificate) chain[i];
            System.out.println(String.format("[%s] %s", i, cert.getSubjectDN()));
            System.out.println(CertificateUtil.getCRLURLs(cert));
        }
    }
}
