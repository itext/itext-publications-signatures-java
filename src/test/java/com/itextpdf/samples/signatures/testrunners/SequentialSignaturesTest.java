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
public class SequentialSignaturesTest extends WrappedSamplesRunner {
    private static final Map<Integer, List<Rectangle>> ignoredAreaMap;

    private static final String ALICE = "./src/test/resources/encryption/alice.crt";
    private static final String BOB = "./src/test/resources/encryption/bob.crt";
    private static final String CAROL = "./src/test/resources/encryption/carol.crt";

    private static final String EXPECTED_ERROR_TEXT = "\n./target/signatures/chapter02/signed_by_carol2.pdf:\n" +
            "Document signatures validation failed!\n\n" +
            "ReportItem{checkName='DocMDP check.', message='Certification signature is applied after the approval " +
            "signature which is not allowed.', cause=null, status=INDETERMINATE}\n" +
            "\n./target/signatures/chapter02/signed_by_carol3.pdf:\n" +
            "Document signatures validation failed!\n\n" +
            "ReportItem{checkName='DocMDP check.', message='Certification signature is applied after the approval " +
            "signature which is not allowed.', cause=null, status=INDETERMINATE}\n" +
            "\n./target/signatures/chapter02/signed_by_carol4.pdf:\n" +
            "Document signatures validation failed!\n\n" +
            "ReportItem{checkName='DocMDP check.', message='Permission \"/DocMDP\" dictionary was removed or " +
            "unexpectedly modified.', cause=null, status=INVALID}\n\n" +
            "ReportItem{checkName='DocMDP check.', message='Document contains more than one " +
            "certification signature.', cause=null, status=INDETERMINATE}\n";

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
        StringBuilder errorTemp = new StringBuilder();
        for (int i = 0; i < resultFiles.length; i++) {
            String currentDest = dest + resultFiles[i];
            String currentCmp = cmp + resultFiles[i];
            try {
                String result = new SignatureTestHelper() {
                    @Override
                    protected void addTrustedCertificates(IssuingCertificateRetriever certificateRetriever,
                                                          List<Certificate> certs)
                            throws CertificateException, IOException {
                        super.addTrustedCertificates(certificateRetriever, certs);
                        CertificateFactory cf = CertificateFactory.getInstance("X.509");
                        Certificate aliceCert = cf.generateCertificate(new FileInputStream(ALICE));
                        Certificate bobCert = cf.generateCertificate(new FileInputStream(BOB));
                        Certificate carolCert = cf.generateCertificate(new FileInputStream(CAROL));
                        certificateRetriever.addTrustedCertificates(Arrays.asList(aliceCert, bobCert, carolCert));
                    }
                }.checkForErrors(currentDest, currentCmp, outPath, ignoredAreaMap);

                if (result != null) {
                    errorTemp.append(result);
                }
            } catch (InterruptedException | IOException | GeneralSecurityException exc) {
                errorTemp.append("Exception has been thrown: ").append(exc.getMessage()).append('\n');
            }
        }

        String errorText = errorTemp.toString();
        if (!errorText.contains(EXPECTED_ERROR_TEXT)) {
            errorText += "\n'signed_by_carol2.pdf', 'signed_by_carol3.pdf' and 'signed_by_carol4' files' signatures " +
                    "are expected to be invalid.\n\n";
        } else {
            // Expected error should be ignored
            errorText = errorText.replace(EXPECTED_ERROR_TEXT, "");
        }

        addError(errorText);
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
