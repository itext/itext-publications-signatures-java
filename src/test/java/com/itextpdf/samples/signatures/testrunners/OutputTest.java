package com.itextpdf.samples.signatures.testrunners;

import com.itextpdf.test.RunnerSearchConfig;
import com.itextpdf.test.WrappedSamplesRunner;

import java.io.UnsupportedEncodingException;
import java.security.Security;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.util.Collection;

@Tag("SampleTest")
public class OutputTest extends WrappedSamplesRunner {
    private PrintStream oldSysOut;
    private ByteArrayOutputStream output;

    public static Collection<Object[]> data() {
        RunnerSearchConfig searchConfig = new RunnerSearchConfig();
        searchConfig.addClassToRunnerSearchPath("com.itextpdf.samples.signatures.chapter01.C1_01_DigestDefault");
        searchConfig.addClassToRunnerSearchPath("com.itextpdf.samples.signatures.chapter01.C1_02_DigestBC");
        searchConfig.addClassToRunnerSearchPath("com.itextpdf.samples.signatures.chapter05.C5_01_SignatureIntegrity");
        searchConfig.addClassToRunnerSearchPath("com.itextpdf.samples.signatures.chapter05.C5_02_SignatureInfo");

        return generateTestsList(searchConfig);
    }

    @Timeout(unit = TimeUnit.MILLISECONDS, value = 60000)
    @ParameterizedTest(name = "{index}: {0}")
    @MethodSource("data")
    public void test(RunnerParams data) throws Exception {
        this.sampleClassParams = data;
        setupSystemOutput();
        Security.removeProvider("BC");

        runSamples();

        resetSystemOutput();
    }

    @Override
    protected void comparePdf(String outPath, String dest, String cmp) throws UnsupportedEncodingException {
        System.out.flush();
        String sysOut = output.toString("UTF-8").replace("\r\n", "\n");

        // The 1st and the last output lines are created by samples runner, so they should be removed
        String[] temp = sysOut.split("\n");
        String[] outputLines = new String[temp.length - 2];
        System.arraycopy(temp, 1, outputLines, 0, temp.length - 2);

        String[] expectedLines = getStringField(sampleClass, "EXPECTED_OUTPUT").split("\n");

        for (int i = 0; i < outputLines.length; ++i) {
            String line = outputLines[i];
            if (!line.trim().equals(expectedLines[i].trim())) {
                addError(String.format("Unexpected output at line %d.\nExpected: %s\ngot: %s",
                        i + 1, expectedLines[i], outputLines[i]));
            }
        }
    }

    private void setupSystemOutput() {
        output = new ByteArrayOutputStream();
        PrintStream ps = new PrintStream(output);
        oldSysOut = System.out;
        System.setOut(ps);
    }

    private void resetSystemOutput() {
        System.setOut(oldSysOut);
    }
}
