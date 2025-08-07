package com.itextpdf.samples.signatures.testrunners;

import com.itextpdf.kernel.geom.Rectangle;
import com.itextpdf.samples.SignatureTestHelper;
import com.itextpdf.signatures.IssuingCertificateRetriever;
import com.itextpdf.test.RunnerSearchConfig;
import com.itextpdf.test.WrappedSamplesRunner;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.lang.reflect.Field;
import java.security.GeneralSecurityException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.*;
import java.util.concurrent.TimeUnit;

@Tag("SampleTest")
public class SignatureWorkflowTest extends WrappedSamplesRunner {
    private static final Map<Integer, List<Rectangle>> ignoredAreaMap;

    private static final String ALICE = "./src/test/resources/encryption/alice.crt";
    private static final String BOB = "./src/test/resources/encryption/bob.crt";
    private static final String CAROL = "./src/test/resources/encryption/carol.crt";
    private static final String DAVE = "./src/test/resources/encryption/dave.crt";

    static {
        ignoredAreaMap = new HashMap<>();
        ignoredAreaMap.put(1, new ArrayList<Rectangle>(Arrays.asList(
                new Rectangle(55, 340, 287, 465))));
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
                    protected void addTrustedCertificates(IssuingCertificateRetriever certificateRetriever,
                                                          List<Certificate> certs)
                            throws CertificateException, IOException {
                        super.addTrustedCertificates(certificateRetriever, certs);
                        CertificateFactory cf = CertificateFactory.getInstance("X.509");
                        Certificate aliceCert = cf.generateCertificate(new FileInputStream(ALICE));
                        Certificate bobCert = cf.generateCertificate(new FileInputStream(BOB));
                        Certificate carolCert = cf.generateCertificate(new FileInputStream(CAROL));
                        Certificate daveCert = cf.generateCertificate(new FileInputStream(DAVE));
                        certificateRetriever.addTrustedCertificates(
                                Arrays.asList(aliceCert, bobCert, carolCert, daveCert));
                    }
                }.checkForErrors(currentDest, currentCmp, outPath, ignoredAreaMap, true));
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
