package com.itextpdf.samples.signatures.testrunners;

import com.itextpdf.test.RunnerSearchConfig;
import com.itextpdf.test.WrappedSamplesRunner;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.lang.reflect.Field;
import java.util.Collection;

import org.junit.Test;
import org.junit.runners.Parameterized;

public class CertificateValidationTest extends WrappedSamplesRunner {
    private ByteArrayOutputStream output = new ByteArrayOutputStream();;
    @Parameterized.Parameters(name = "{index}: {0}")
    public static Collection<Object[]> data() {
        RunnerSearchConfig searchConfig = new RunnerSearchConfig();
        searchConfig.addClassToRunnerSearchPath("com.itextpdf.samples.signatures.chapter05.C5_03_CertificateValidation");

        return generateTestsList(searchConfig);
    }

    @Test(timeout = 60000)
    public void test() throws Exception {
        runSamples();
    }

    @Override
    protected void initClass() {
        super.initClass();
        setSampleOutStream(sampleClass);
    }

    @Override
    protected void comparePdf(String outPath, String dest, String cmp) throws Exception {
        String sysOut = output.toString("UTF-8").replace("\r\n", "\n");
        String[] outputLines = sysOut.split("\n");

        String[] expectedLines = getStringField(sampleClass, "EXPECTED_OUTPUT").split("\n");

        for (int i = 0; i < outputLines.length; ++i) {
            String line = outputLines[i];
            if (!line.trim().equals(expectedLines[i].trim())) {
                addError(String.format("Unexpected output at line %d.\nExpected: %s\ngot: %s",
                        i + 1, expectedLines[i], outputLines[i]));
            }
        }
    }

    private void setSampleOutStream(Class<?> c) {
        try {
            Field field = c.getDeclaredField("OUT_STREAM");
            if (field == null) {
                return;
            }

            boolean access = field.isAccessible();
            field.setAccessible(true);
            Object obj = field.get(null);
            if (obj == null || !(obj instanceof PrintStream)) {
                return;
            }

            PrintStream stream = new PrintStream(output);
            field.set(c, stream);
            field.setAccessible(access);
        } catch (NoSuchFieldException | IllegalAccessException e) {
            addError(e.getMessage());
        }
    }
}
