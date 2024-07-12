package com.itextpdf.samples.signatures.testrunners;

import com.itextpdf.kernel.geom.Rectangle;
import com.itextpdf.samples.SignatureTestHelper;
import com.itextpdf.samples.signatures.chapter02.C2_11_SignatureWorkflow;
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
public class SignatureWorkflowTest extends WrappedSamplesRunner {
    private static final Map<Integer, List<Rectangle>> ignoredAreaMap;

    static {
        ignoredAreaMap = new HashMap<>();
        ignoredAreaMap.put(1, new ArrayList<Rectangle>(Arrays.asList(
                new Rectangle(55, 440, 287, 365))));
    }

    public static Collection<Object[]> data() {
        RunnerSearchConfig searchConfig = new RunnerSearchConfig();
        searchConfig.addClassToRunnerSearchPath("com.itextpdf.samples.signatures.chapter02.C2_11_SignatureWorkflow");

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
                addError(new SignatureTestHelper() {
                    @Override
                    protected void initKeyStoreForVerification(KeyStore ks)
                            throws IOException, NoSuchAlgorithmException, CertificateException, KeyStoreException {
                        super.initKeyStoreForVerification(ks);
                        ks.setCertificateEntry("alice", loadCertificateFromKeyStore(C2_11_SignatureWorkflow.ALICE,
                                C2_11_SignatureWorkflow.PASSWORD));
                        ks.setCertificateEntry("bob", loadCertificateFromKeyStore(C2_11_SignatureWorkflow.BOB,
                                C2_11_SignatureWorkflow.PASSWORD));
                        ks.setCertificateEntry("carol", loadCertificateFromKeyStore(C2_11_SignatureWorkflow.CAROL,
                                C2_11_SignatureWorkflow.PASSWORD));
                        ks.setCertificateEntry("dave", loadCertificateFromKeyStore(C2_11_SignatureWorkflow.DAVE,
                                C2_11_SignatureWorkflow.PASSWORD));
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
