package com.itextpdf.signatures.chapter01;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * Class to demonstrate the use of message digests for passwords.
 */
public class PasswordMD {
    
    /**  The digest of a password. */
    protected byte[] digest;
    
    /**  The algorithm that will create the digest. */
    protected MessageDigest md;
    
    /**
     * Instantiates a new password ,essage digest.
     *
     * @param password the password
     * @param algorithm the algorithm
     * @param provider the provider
     * @throws GeneralSecurityException the general security exception
     */
    protected PasswordMD(String password, String algorithm, String provider)
        throws GeneralSecurityException {
        if (provider == null)
            md = MessageDigest.getInstance(algorithm);
        else
            md = MessageDigest.getInstance(algorithm, provider);
        digest = md.digest(password.getBytes());
    }
    
    /**
     * Gets the size of the digest in bytes.
     *
     * @return the digest size in bytes
     */
    public int getDigestSize() {
        return digest.length;
    }
    
    /**
     * Gets the digest as a hexadecimal string.
     *
     * @return the digest as a hexadecimal string
     */
    public String getDigestAsHexString() {
        return new BigInteger(1, digest).toString(16);
    }
    
    /**
     * Check a password.
     *
     * @param password the password
     * @return true, if successful
     */
    public boolean checkPassword(String password) {
        return MessageDigest.isEqual(digest, md.digest(password.getBytes()));
    }
    
    /**
     * Show test.
     *
     * @param algorithm the algorithm
     * @throws GeneralSecurityException the general security exception
     */
    public static void showTestDefault(String algorithm) {
        try {
            PasswordMD app = new PasswordMD("password", algorithm, null);
            System.out.println("Digest using " + algorithm + ": "
                    + app.getDigestSize());
            System.out.println("Digest: " + app.getDigestAsHexString());
            System.out.println("Is the password 'password'? "
                    + app.checkPassword("password"));
            System.out.println("Is the password 'secret'? "
                + app.checkPassword("secret"));
        } catch (NoSuchAlgorithmException e) {
            System.out.println(e.getMessage());
        } catch (GeneralSecurityException e) {
            System.out.println(e.getMessage());
        }
    }

    
    /**
     * Show test.
     *
     * @param algorithm the algorithm
     * @throws GeneralSecurityException the general security exception
     */
    public static void showTestBC(String algorithm) {
        try {
            PasswordMD app = new PasswordMD("password", algorithm, "BC");
            System.out.println("Digest using " + algorithm + ": "
                    + app.getDigestSize());
            System.out.println("Digest: " + app.getDigestAsHexString());
            System.out.println("Is the password 'password'? "
                    + app.checkPassword("password"));
            System.out.println("Is the password 'secret'? "
                + app.checkPassword("secret"));
        } catch (NoSuchAlgorithmException e) {
            System.out.println(e.getMessage());
        } catch (GeneralSecurityException e) {
            System.out.println(e.getMessage());
        }
    }
    
    /**
     * The main method.
     *
     * @param args the arguments
     */
    public static void main(String[] args) {
    	showTestDefault("MD2");
    	showTestDefault("MD5");
    	showTestDefault("SHA-1");
    	showTestDefault("SHA-224");
    	showTestDefault("SHA-256");
    	showTestDefault("SHA-384");
    	showTestDefault("SHA-512");
    	showTestDefault("RIPEMD128");
    	showTestDefault("RIPEMD160");
    	showTestDefault("RIPEMD256");
    	Security.addProvider(new BouncyCastleProvider());
    	showTestBC("MD5");
    	showTestBC("SHA-1");
    	showTestBC("SHA-224");
    	showTestBC("SHA-256");
    	showTestBC("SHA-384");
    	showTestBC("SHA-512");
    	showTestBC("RIPEMD128");
    	showTestBC("RIPEMD160");
    	showTestBC("RIPEMD256");
    }
}
