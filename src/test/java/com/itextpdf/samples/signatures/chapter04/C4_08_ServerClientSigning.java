package com.itextpdf.samples.signatures.chapter04;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.*;

import java.util.List;

public class C4_08_ServerClientSigning {
    public static final String DEST = "./target/signatures/chapter04/";

    public static final String KEYSTORE = "./src/test/resources/encryption/certificate.p12";
    public static final String CERT = "./src/test/resources/encryption/bruno.crt";
    public static final String PRE = "http://demo.itextsupport.com/SigningApp/presign";
    public static final String POST = "http://demo.itextsupport.com/SigningApp/postsign";

    public static final String[] RESULT_FILES = new String[] {
            "hello_server2.pdf"
    };

    public static final char[] PASSWORD = "testpassphrase".toCharArray();

    public static void main(String[] args) throws IOException, GeneralSecurityException {
        File file = new File(DEST);
        file.mkdirs();

        // Make a connection to a PreSign servlet to ask to create a document,
        // then calculate its hash and send it to us
        URL url = new URL(PRE);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setDoOutput(true);
        conn.setRequestMethod("POST");
        conn.connect();

        // Upload your self-signed certificate
        OutputStream os = conn.getOutputStream();
        FileInputStream fis = new FileInputStream(CERT);
        int read;
        byte[] data = new byte[256];
        while ((read = fis.read(data, 0, data.length)) != -1) {
            os.write(data, 0, read);
        }

        os.flush();
        os.close();

        // Use cookies to maintain a session
        List<String> cookies = conn.getHeaderFields().get("Set-Cookie");

        // Receive a hash that needs to be signed
        InputStream is = conn.getInputStream();
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        data = new byte[256];
        while ((read = is.read(data)) != -1) {
            baos.write(data, 0, read);
        }

        is.close();
        byte[] hash = baos.toByteArray();

        BouncyCastleProvider provider = new BouncyCastleProvider();
        Security.addProvider(provider);
        // Load your private key from the key store
        KeyStore ks = KeyStore.getInstance("pkcs12", provider.getName());
        ks.load(new FileInputStream(KEYSTORE), PASSWORD);
        String alias = ks.aliases().nextElement();
        PrivateKey pk = (PrivateKey) ks.getKey(alias, PASSWORD);

        // Sign the hash received from the server
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initSign(pk);
        sig.update(hash);
        data = sig.sign();

        // Make a connection to the PostSign Servlet to send the signed bytes to the server.
        url = new URL(POST);
        conn = (HttpURLConnection) url.openConnection();
        for (String cookie : cookies) {
            conn.addRequestProperty("Cookie", cookie.split(";", 2)[0]);
        }

        conn.setDoOutput(true);
        conn.setRequestMethod("POST");
        conn.connect();

        //Upload the signed bytes
        os = conn.getOutputStream();
        os.write(data);
        os.flush();
        os.close();

        // Receive the signed document
        is = conn.getInputStream();
        FileOutputStream fos = new FileOutputStream(DEST + RESULT_FILES[0]);
        data = new byte[256];
        while ((read = is.read(data)) != -1) {
            fos.write(data, 0, read);
        }

        is.close();
        fos.flush();
        fos.close();
    }
}
