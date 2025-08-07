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
public class LockFieldsTest extends WrappedSamplesRunner {
    private static final Map<Integer, List<Rectangle>> ignoredAreaMap;

    private static final String ALICE = "./src/test/resources/encryption/alice.crt";
    private static final String BOB = "./src/test/resources/encryption/bob.crt";
    private static final String CAROL = "./src/test/resources/encryption/carol.crt";
    private static final String DAVE = "./src/test/resources/encryption/dave.crt";

    private static final String EXPECTED_ERROR_TEXT =
            "\n./target/signatures/chapter02/step_5_signed_by_alice_and_bob_broken_by_chuck.pdf:\n" +
                    "Document signatures validation failed!\n\n" +
                    "ReportItem{checkName='FieldMDP check.', message='Locked form field \"approved_bob\" or " +
                    "one of its widgets was modified.', cause=null, status=INVALID}\n" +
                    "\n./target/signatures/chapter02/step_6_signed_by_dave_broken_by_chuck.pdf:\n" +
                    "Document signatures validation failed!\n\n" +
                    "ReportItem{checkName='DocMDP check.', message='Form field approved_carol was removed or " +
                    "unexpectedly modified.', cause=null, status=INVALID}\n\n" +
                    "ReportItem{checkName='DocMDP check.', message='PDF document AcroForm contains changes " +
                    "other than document timestamp (docMDP level >= 1), form fill-in and digital signatures " +
                    "(docMDP level >= 2), adding or editing annotations (docMDP level 3), which are not allowed.', " +
                    "cause=null, status=INVALID}\n";

    static {
        ignoredAreaMap = new HashMap<>();
        ignoredAreaMap.put(1, new ArrayList<Rectangle>(Arrays.asList(
                new Rectangle(55, 425, 287, 380))));
    }

    public static Collection<Object[]> data() {
        RunnerSearchConfig searchConfig = new RunnerSearchConfig();
        searchConfig.addClassToRunnerSearchPath("com.itextpdf.samples.signatures.chapter02.C2_12_LockFields");

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

                /* TODO: DEVSIX-1623
                 * For some reason Acrobat recognizes last signature in the
                 * 'step_4_signed_by_alice_bob_carol_and_dave.pdf' file as invalid.
                 * It happens only if LockPermissions is set to NO_CHANGES_ALLOWED for the last signature form field.
                 * It's still unclear, whether it's iText messes up the document or it's Acrobat bug.
                 */
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
                        Certificate daveCert = cf.generateCertificate(new FileInputStream(DAVE));
                        certificateRetriever.addTrustedCertificates(
                                Arrays.asList(aliceCert, bobCert, carolCert, daveCert));
                    }
                }.checkForErrors(currentDest, currentCmp, outPath, ignoredAreaMap, true);

                if (result != null) {
                    errorTemp.append(result);
                }
            } catch (InterruptedException | IOException | GeneralSecurityException exc) {
                errorTemp.append("Exception has been thrown: ").append(exc.getMessage()).append('\n');
            }
        }

        String errorText = errorTemp.toString();
        if (!errorText.contains(EXPECTED_ERROR_TEXT)) {
            errorText += "\n'step_5_signed_by_alice_and_bob_broken_by_chuck.pdf' and " +
                    "'step_6_signed_by_dave_broken_by_chuck.pdf' files' signatures are expected to be invalid.\n\n";
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
