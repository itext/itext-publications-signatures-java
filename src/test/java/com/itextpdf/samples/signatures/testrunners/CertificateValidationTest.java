package com.itextpdf.samples.signatures.testrunners;

import com.itextpdf.test.RunnerSearchConfig;
import com.itextpdf.test.WrappedSamplesRunner;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.lang.reflect.Field;
import java.util.Collection;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

public class CertificateValidationTest extends WrappedSamplesRunner {
    private final ByteArrayOutputStream output = new ByteArrayOutputStream();

    public static Collection<Object[]> data() {
        RunnerSearchConfig searchConfig = new RunnerSearchConfig();
        searchConfig.addClassToRunnerSearchPath("com.itextpdf.samples.signatures.chapter05.C5_03_CertificateValidation");

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
    protected void initClass() {
        super.initClass();
        setSampleOutStream(sampleClass);
    }

    @Override
    protected void comparePdf(String outPath, String dest, String cmp) throws Exception {
        String sysOut = output.toString("UTF-8").replace("\r\n", "\n");
        String[] outputLines = sysOut.split("\n");

        String[] expectedLines = getStringField(sampleClass, "EXPECTED_OUTPUT").split("\n");
        String ignoreString = getStringField(sampleClass, "STRING_TO_IGNORE");

        for (int i = 0; i < outputLines.length; ++i) {
            String line = outputLines[i];
            if (ignoreString != null && line.contains(ignoreString)) {
                continue;
            }

            if (!line.trim().equals(expectedLines[i].trim())) {
                addError(String.format("Unexpected output at line %d.\nExpected: %s\ngot: %s",
                        i + 1, expectedLines[i], outputLines[i]));
            }
        }
    }

    private void setSampleOutStream(Class<?> c) {
        try {
            Field field = c.getDeclaredField("OUT_STREAM");

            boolean access = field.isAccessible();
            field.setAccessible(true);
            Object obj = field.get(null);
            if (!(obj instanceof PrintStream)) {
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
