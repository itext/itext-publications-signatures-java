package com.itextpdf.samples.signatures.testrunners;

import com.itextpdf.kernel.geom.Rectangle;
import com.itextpdf.samples.SignatureTestHelper;
import com.itextpdf.samples.signatures.chapter04.C4_07_ClientServerSigning;
import com.itextpdf.signatures.IssuingCertificateRetriever;
import com.itextpdf.test.RunnerSearchConfig;
import com.itextpdf.test.WrappedSamplesRunner;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.File;
import java.io.IOException;
import java.lang.reflect.Field;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.*;
import java.util.concurrent.TimeUnit;

@Tag("SampleTest")
public class ClientServerSigningTest extends WrappedSamplesRunner {
    private static final Map<Integer, List<Rectangle>> ignoredAreaMap;

    private static final String EXPECTED_ERROR_TEXT = "\n./target/signatures/chapter04/hello_server.pdf:\n" +
            "Document signatures validation failed!\n\n" +
            "CertificateReportItem{baseclass=\n" +
            "ReportItem{checkName='Required certificate extensions check.', message=" +
            "'Required extension 2.5.29.15 is missing or incorrect.', cause=null, status=INVALID}\n" +
            "certificate=CN=Unknown, OU=Unknown, O=Unknown, L=Unknown, ST=Unknown, C=Unknown}\n";

    static {
        ignoredAreaMap = new HashMap<>();
        ignoredAreaMap.put(1, new ArrayList<Rectangle>(Arrays.asList(
                new Rectangle(36, 648, 200, 100))));
    }

    public static Collection<Object[]> data() {
        RunnerSearchConfig searchConfig = new RunnerSearchConfig();
        searchConfig.addClassToRunnerSearchPath("com.itextpdf.samples.signatures.chapter04.C4_07_ClientServerSigning");

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
                        URL certUrl = new URL(C4_07_ClientServerSigning.CERT);
                        CertificateFactory cf = CertificateFactory.getInstance("X.509");
                        Certificate itextCert = cf.generateCertificate(certUrl.openStream());
                        certificateRetriever.addTrustedCertificates(Collections.singleton(itextCert));
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
            errorText += "\n'hello_server.pdf' file's signature is expected to be invalid due to " +
                    "missing key usage extension for signing certificate.\n\n";
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
