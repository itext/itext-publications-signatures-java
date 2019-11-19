/*
    This file is part of the iText (R) project.
    Copyright (c) 1998-2019 iText Group NV
    Authors: iText Software.

    For more information, please contact iText Software at this address:
    sales@itextpdf.com
 */
package com.itextpdf.samples.signatures.testrunners;

import com.itextpdf.kernel.geom.Rectangle;
import com.itextpdf.samples.SignatureTest;
import com.itextpdf.samples.signatures.chapter02.C2_12_LockFields;
import com.itextpdf.test.RunnerSearchConfig;
import com.itextpdf.test.WrappedSamplesRunner;

import java.io.File;
import java.io.IOException;
import java.lang.reflect.Field;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.Test;
import org.junit.runners.Parameterized;

public class LockFieldsTest extends WrappedSamplesRunner {
    private static final Map<Integer, List<Rectangle>> ignoredAreaMap;

    static {
        ignoredAreaMap = new HashMap<>();
        ignoredAreaMap.put(1, new ArrayList<Rectangle>(Arrays.asList(
                new Rectangle(55, 425, 287, 380))));
    }

    @Parameterized.Parameters(name = "{index}: {0}")
    public static Collection<Object[]> data() {
        RunnerSearchConfig searchConfig = new RunnerSearchConfig();
        searchConfig.addClassToRunnerSearchPath("com.itextpdf.samples.signatures.chapter02.C2_12_LockFields");

        return generateTestsList(searchConfig);
    }

    @Test(timeout = 60000)
    public void test() throws Exception {
        runSamples();
    }

    @Override
    protected void comparePdf(String outPath, String dest, String cmp) {
        String[] resultFiles = getResultFiles(sampleClass);
        for (int i = 0; i < resultFiles.length; i++) {
            String currentDest = dest + resultFiles[i];
            String currentCmp = cmp + resultFiles[i];
            try {

                /* TODO: DEVSIX-1623
                 * For some reason Acrobat recognizes last signature in the
                 * 'step_4_signed_by_alice_bob_carol_and_dave.pdf' file as invalid.
                 * It happens only if LockPermissions is set to NO_CHANGES_ALLOWED for the last signature form field.
                 * It's still unclear, whether it's iText messes up the document or it's Acrobat bug.
                 */
                 /* iText doesn't recognize invalidated signatures in those files,
                 * because we don't check changes in new revisions against old signatures (permissions,
                 * certifications, content changes), however signatures themselves are not broken.
                 */
                addError(new SignatureTest() {
                    @Override
                    protected void initKeyStoreForVerification(KeyStore ks)
                            throws IOException, NoSuchAlgorithmException, CertificateException, KeyStoreException {
                        super.initKeyStoreForVerification(ks);
                        ks.setCertificateEntry("alice", loadCertificateFromKeyStore(C2_12_LockFields.ALICE,
                                C2_12_LockFields.PASSWORD));
                        ks.setCertificateEntry("bob", loadCertificateFromKeyStore(C2_12_LockFields.BOB,
                                C2_12_LockFields.PASSWORD));
                        ks.setCertificateEntry("carol", loadCertificateFromKeyStore(C2_12_LockFields.CAROL,
                                C2_12_LockFields.PASSWORD));
                        ks.setCertificateEntry("dave", loadCertificateFromKeyStore(C2_12_LockFields.DAVE,
                                C2_12_LockFields.PASSWORD));
                    }
                }.checkForErrors(currentDest, currentCmp, outPath, ignoredAreaMap));
            } catch (InterruptedException | IOException | GeneralSecurityException exc) {
                addError("Exception has been thrown: " + exc.getMessage());
            }
        }
    }

    @Override
    protected String getOutPath(String dest) {
        return new File(dest).getParent();
    }

    private static String[] getResultFiles(Class<?> c) {
        try {
            Field field = c.getField("RESULT_FILES");
            if (field == null) {
                return null;
            }
            Object obj = field.get(null);
            if (obj == null || !(obj instanceof String[])) {
                return null;
            }
            return (String[]) obj;
        } catch (Exception e) {
            return null;
        }
    }
}
