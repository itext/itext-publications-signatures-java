package com.itextpdf.samples.signatures.testrunners;

import com.itextpdf.kernel.geom.Rectangle;
import com.itextpdf.samples.SignatureTestHelper;
import com.itextpdf.test.RunnerSearchConfig;
import com.itextpdf.test.WrappedSamplesRunner;

import java.io.File;
import java.io.IOException;
import java.lang.reflect.Field;
import java.security.GeneralSecurityException;
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
public class SignatureTypesTest extends WrappedSamplesRunner {
    private static final Map<Integer, List<Rectangle>> ignoredAreaMap;

    private static final String EXPECTED_ERROR_TEXT =
            "\n./target/signatures/chapter02/hello_level_3_annotated.pdf:\n" +
                    "Document signatures validation failed!\n\n" +
                    "ReportItem{checkName='DocMDP check.', message='Page annotations were unexpectedly modified.', " +
                    "cause=null, status=INVALID}\n" +
                    "\n./target/signatures/chapter02/hello_level_4_annotated.pdf:\n" +
                    "Document signatures validation failed!\n\n" +
                    "ReportItem{checkName='DocMDP check.', message='Page annotations were unexpectedly modified.', " +
                    "cause=null, status=INVALID}\n" +
                    "\n./target/signatures/chapter02/hello_level_1_annotated_wrong.pdf:\n" +
                    "Document signatures validation failed!\n\n" +
                    "ReportItem{checkName='DocMDP check.', message='Not possible to identify document revision " +
                    "corresponding to the first signature in the document.', cause=null, status=INVALID}\n\n" +
                    "ReportItem{checkName='Signature verification check.', message='Unexpected exception occurred " +
                    "during document revisions retrieval.', cause=com.itextpdf.io.exceptions.IOException: " +
                    "PDF startxref not found., status=INDETERMINATE}\n" +
                    "\n./target/signatures/chapter02/hello_level_1_text.pdf:\n" +
                    "Document signatures validation failed!\n\n" +
                    "ReportItem{checkName='DocMDP check.', message='Page was unexpectedly modified.', " +
                    "cause=null, status=INVALID}\n" +
                    "\n./target/signatures/chapter02/hello_level_4_double.pdf:\n" +
                    "Document signatures validation failed!\n\n" +
                    "ReportItem{checkName='DocMDP check.', message='New PDF document revision contains " +
                    "unexpected form field \"Signature2\".', cause=null, status=INVALID}\n\n" +
                    "ReportItem{checkName='DocMDP check.', message='PDF document AcroForm contains changes " +
                    "other than document timestamp (docMDP level >= 1), " +
                    "form fill-in and digital signatures (docMDP level >= 2), " +
                    "adding or editing annotations (docMDP level 3), which are not allowed.', " +
                    "cause=null, status=INVALID}\n";

    static {
        ignoredAreaMap = new HashMap<>();
        ignoredAreaMap.put(1, new ArrayList<Rectangle>(Arrays.asList(
                new Rectangle(72, 675, 170, 20),
                new Rectangle(72, 725, 170, 20))));
    }

    public static Collection<Object[]> data() {
        RunnerSearchConfig searchConfig = new RunnerSearchConfig();
        searchConfig.addClassToRunnerSearchPath("com.itextpdf.samples.signatures.chapter02.C2_09_SignatureTypes");

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
                String result = new SignatureTestHelper()
                        .checkForErrors(currentDest, currentCmp, outPath, ignoredAreaMap);

                if (result != null) {
                    errorTemp.append(result);
                }

            } catch (InterruptedException | IOException | GeneralSecurityException exc) {
                errorTemp.append("Exception has been thrown: ").append(exc.getMessage()).append('\n');
            }
        }

        String errorText = errorTemp.toString();
        if (!errorText.contains(EXPECTED_ERROR_TEXT)) {
            errorText += "\n'hello_level_3_annotated.pdf', 'hello_level_4_annotated.pdf', " +
                    "'hello_level_1_annotated_wrong.pdf', 'hello_level_1_text.pdf' and 'hello_level_4_double.pdf' " +
                    "files' signatures are expected to be invalid.\n\n";
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
