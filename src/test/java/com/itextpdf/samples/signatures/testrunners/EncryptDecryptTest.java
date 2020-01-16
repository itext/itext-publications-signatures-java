/*
    This file is part of the iText (R) project.
    Copyright (c) 1998-2020 iText Group NV
    Authors: iText Software.

    For more information, please contact iText Software at this address:
    sales@itextpdf.com
 */
package com.itextpdf.samples.signatures.testrunners;

import com.itextpdf.test.RunnerSearchConfig;
import com.itextpdf.test.WrappedSamplesRunner;
import com.itextpdf.test.annotations.type.SampleTest;

import java.io.UnsupportedEncodingException;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.runners.Parameterized;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.util.Collection;

@Category(SampleTest.class)
public class EncryptDecryptTest extends WrappedSamplesRunner {
    private PrintStream oldSysOut;
    private ByteArrayOutputStream output;

    private static final String EXPECTED_OUTPUT = "Let's encrypt 'secret message' with a public key\n" +
            "Encrypted message: 117831320649a4b0f420466c45a2368cae6d5edf8a99e9d04c69e8a6f63c86167764" +
            "06928a11b9f0e01101d1e5d90558f99152c91fd175fb6bb7b1282e6b2d2c955d1596d923c09597a6de3b15aa6" +
            "f0ec720f0958a5b8180ad4042121dadef835804f653846a06280e9661e2dcf4eb89afb3fc3b61e9ccccc39c" +
            "d8ca3714145e48cc9aa4013f13e3407a669117d95b173a368fab7fac1678c06c68fc79c5019718e52119cee13" +
            "55c3fae7a47a8916789b0797fef9c94bca99753fd2f33d1e0849128a9c3a3e26bc09199e66d8831294b97ccdf7" +
            "a5b6d37857ed1e55da946f23d4f87abc48f1b9e72e6e65f15843f24cf5784b619eb25acd19344729e37481779\n" +
            "Let's decrypt it with the corresponding private key\n" +
            "secret message\n" +
            "You can also encrypt the message with a private key\n" +
            "Encrypted message: 289c63ccb0dc49a2e9f0f3e0dcabcd036f503f05abbe1dc110ed8364856e04a875c7" +
            "c0adef9b407c40bb77921540617aa85693e13b3fefe88b2ab9449b3a6fd81bce5ee3e7d2b81f0cf0593da8" +
            "3c94f8e203cc8690022df0e6c8ebb0c001c5241ada3033e4b9d1060ef167b4b6b0f850b4324fb8b4b48dee1" +
            "691214ea435e81f825f036e12512b283c7a08e2d9e24c2910c2989797a70943701450eeda86d968d432829ee" +
            "0764b93c636c988de7b9dca198a8150a31f8cb2fedb498b7908abec59f601ce47b1ab0deb632b4a6f904b5e969c5a" +
            "70cb50c749ea2467f0bcd504d85a7d1a477e29fc4767695e00c141f82ec75ede6d0c342182f7d9d8f72faa3aec\n" +
            "Now you need the public key to decrypt it\n" +
            "secret message\n";

    @Parameterized.Parameters(name = "{index}: {0}")
    public static Collection<Object[]> data() {
        RunnerSearchConfig searchConfig = new RunnerSearchConfig();
        searchConfig.addClassToRunnerSearchPath("com.itextpdf.samples.signatures.chapter01.C1_03_EncryptDecrypt");

        return generateTestsList(searchConfig);
    }

    @Test(timeout = 60000)
    public void test() throws Exception {
        setupSystemOutput();

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

        String[] expectedLines = EXPECTED_OUTPUT.split("\n");

        for (int i = 0; i < outputLines.length; ++i) {
            String line = outputLines[i];

            // Encrypted message line can be different at each run,
            // so the line with encrypted message should be ignored.
            if (!line.startsWith("Encrypted message: ") && !line.trim().equals(expectedLines[i].trim())) {
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
