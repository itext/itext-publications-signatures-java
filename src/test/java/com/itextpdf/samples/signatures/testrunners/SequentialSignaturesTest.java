package com.itextpdf.samples.signatures.testrunners;

import com.itextpdf.kernel.geom.Rectangle;
import com.itextpdf.samples.SignatureTestHelper;
import com.itextpdf.samples.signatures.chapter02.C2_10_SequentialSignatures;
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
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

@Tag("SampleTest")
public class SequentialSignaturesTest extends WrappedSamplesRunner {
    private static final Map<Integer, List<Rectangle>> ignoredAreaMap;

    static {
        ignoredAreaMap = new HashMap<>();
        ignoredAreaMap.put(1, new ArrayList<Rectangle>(Arrays.asList(
                new Rectangle(55, 550, 287, 255))));
    }

    public static Collection<Object[]> data() {
        RunnerSearchConfig searchConfig = new RunnerSearchConfig();
        searchConfig.addClassToRunnerSearchPath("com.itextpdf.samples.signatures.chapter02.C2_10_SequentialSignatures");

        return generateTestsList(searchConfig);
    }

    @Timeout(unit = TimeUnit.MILLISECONDS, value = 60000)
    @ParameterizedTest(name = "{index}: {0}")
    @MethodSource("data")
    public void test(RunnerParams data) throws Exception {
        this.sampleClassParams = data;
        runSamples();
    }

    @Override
    protected void comparePdf(String outPath, String dest, String cmp) {
        String[] resultFiles = getResultFiles(sampleClass);
        for (int i = 0; i < resultFiles.length; i++) {
            String currentDest = dest + resultFiles[i];
            String currentCmp = cmp + resultFiles[i];
            try {

                /* 'signed_by_carol2.pdf' file should be invalid from dig sig point of view,
                 * however both Acrobat and iText doesn't recognize it (certification signatures shall be
                 * the first signatures in the document, still signatures themselves are not broken in it).
                 */
                /*  iText doesn't recognize invalidated signatures in "signed_by_carol3.pdf",
                 * "signed_by_carol4.pdf" files, because we don't check that document shall
                 * have only one certification signature and it shall be the first one.
                 * However signatures themselves are not broken.
                 */
                addError(new SignatureTestHelper() {
                    @Override
                    protected void initKeyStoreForVerification(KeyStore ks)
                            throws IOException, NoSuchAlgorithmException, CertificateException, KeyStoreException {
                        super.initKeyStoreForVerification(ks);
                        ks.setCertificateEntry("alice", loadCertificateFromKeyStore(C2_10_SequentialSignatures.ALICE,
                                C2_10_SequentialSignatures.PASSWORD));
                        ks.setCertificateEntry("bob", loadCertificateFromKeyStore(C2_10_SequentialSignatures.BOB,
                                C2_10_SequentialSignatures.PASSWORD));
                        ks.setCertificateEntry("carol", loadCertificateFromKeyStore(C2_10_SequentialSignatures.CAROL,
                                C2_10_SequentialSignatures.PASSWORD));
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
