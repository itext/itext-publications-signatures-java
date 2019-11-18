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
import com.itextpdf.test.RunnerSearchConfig;
import com.itextpdf.test.WrappedSamplesRunner;
import com.itextpdf.test.annotations.type.SampleTest;

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
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.runners.Parameterized;

@Category(SampleTest.class)
public class SignatureTypesTest extends WrappedSamplesRunner {
    private static final Map<Integer, List<Rectangle>> ignoredAreaMap;

    private static final String EXPECTED_ERROR_TEXT =
            "\n./target/signatures/chapter02/hello_level_1_annotated_wrong.pdf:"
                    + "\n\"sig\" signature integrity is invalid\n\n";

    static {
        ignoredAreaMap = new HashMap<>();
        ignoredAreaMap.put(1, new ArrayList<Rectangle>(Arrays.asList(
                new Rectangle(72, 675, 170, 20),
                new Rectangle(72, 725, 170, 20))));
    }

    @Parameterized.Parameters(name = "{index}: {0}")
    public static Collection<Object[]> data() {
        RunnerSearchConfig searchConfig = new RunnerSearchConfig();
        searchConfig.addClassToRunnerSearchPath("com.itextpdf.samples.signatures.chapter02.C2_09_SignatureTypes");

        return generateTestsList(searchConfig);
    }

    @Test(timeout = 60000)
    public void test() throws Exception {
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

                /* iText doesn't recognize invalidated signatures in "hello_level_3_annotated.pdf",
                 * "hello_level_4_annotated.pdf", "hello_level_1_text.pdf", "hello_level_4_double.pdf"
                 * files, because we don't check changes in new revisions against old signatures
                 * (permissions, certifications, content changes),
                 * however signatures themselves are not broken.
                 */
                String result = new SignatureTest()
                        .checkForErrors(currentDest, currentCmp, outPath, ignoredAreaMap);

                if (result != null) {
                    errorTemp.append(result);
                }

            } catch (InterruptedException | IOException | GeneralSecurityException exc) {
                errorTemp.append("Exception has been thrown: ").append(exc.getMessage());
            }
        }

        String errorText = errorTemp.toString();
        if (errorText.equals("") || !errorText.contains(EXPECTED_ERROR_TEXT)) {
            errorText += "\n'hello_level_1_annotated_wrong.pdf' file's signature "
                    + "was expected to be invalid.\n\n";
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
