/*
    This file is part of the iText (R) project.
    Copyright (c) 1998-2022 iText Group NV
    Authors: iText Software.

    For more information, please contact iText Software at this address:
    sales@itextpdf.com
 */
package com.itextpdf.samples.signatures.testrunners;

import com.itextpdf.io.font.FontCache;
import com.itextpdf.io.font.FontProgramFactory;
import com.itextpdf.kernel.geom.Rectangle;
import com.itextpdf.licensing.base.LicenseKey;
import com.itextpdf.samples.SignatureTestHelper;
import com.itextpdf.test.RunnerSearchConfig;
import com.itextpdf.test.WrappedSamplesRunner;
import com.itextpdf.test.annotations.type.SampleTest;

import java.io.File;
import java.io.FileInputStream;
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
public class SignatureRunnerTest extends WrappedSamplesRunner {
    private static final Map<String, List<Rectangle>> classAreaMap;

    static {
        classAreaMap = new HashMap<>();
        classAreaMap.put("com.itextpdf.samples.signatures.chapter02.C2_01_SignHelloWorld",
                new ArrayList<Rectangle>(Arrays.asList(new Rectangle(36, 648, 200, 100))));
        classAreaMap.put("com.itextpdf.samples.signatures.chapter02.C2_02_SignHelloWorldWithTempFile",
                new ArrayList<Rectangle>(Arrays.asList(new Rectangle(36, 648, 200, 100))));
        classAreaMap.put("com.itextpdf.samples.signatures.chapter02.C2_03_SignEmptyField",
                new ArrayList<Rectangle>(Arrays.asList(new Rectangle(46, 472, 287, 255))));
        classAreaMap.put("com.itextpdf.samples.signatures.chapter02.C2_04_CreateEmptyField",
                new ArrayList<Rectangle>(Arrays.asList(new Rectangle(82, 672, 190, 20))));
        classAreaMap.put("com.itextpdf.samples.signatures.chapter02.C2_05_CustomAppearance",
                new ArrayList<Rectangle>(Arrays.asList(new Rectangle(46, 472, 287, 255))));
        classAreaMap.put("com.itextpdf.samples.signatures.chapter02.C2_06_SignatureAppearance",
                new ArrayList<Rectangle>(Arrays.asList(new Rectangle(46, 472, 287, 255))));
        classAreaMap.put("com.itextpdf.samples.signatures.chapter02.C2_07_SignatureAppearances",
                new ArrayList<Rectangle>(Arrays.asList(new Rectangle(46, 472, 287, 255))));
        classAreaMap.put("com.itextpdf.samples.signatures.chapter02.C2_08_SignatureMetadata",
                new ArrayList<Rectangle>(Arrays.asList(new Rectangle(46, 472, 287, 255))));
        classAreaMap.put("com.itextpdf.samples.signatures.chapter03.C3_01_SignWithCAcert",
                new ArrayList<Rectangle>(Arrays.asList(new Rectangle(36, 648, 200, 100))));
        classAreaMap.put("com.itextpdf.samples.signatures.chapter04.C4_08_ServerClientSigning",
                new ArrayList<Rectangle>(Arrays.asList(new Rectangle(38, 758, 72, 5))));
        classAreaMap.put("com.itextpdf.samples.signatures.chapter04.C4_09_DeferredSigning",
                new ArrayList<Rectangle>(Arrays.asList(new Rectangle(36, 748, 200, 100))));
    }

    @Parameterized.Parameters(name = "{index}: {0}")
    public static Collection<Object[]> data() {
        RunnerSearchConfig searchConfig = new RunnerSearchConfig();
        searchConfig.addPackageToRunnerSearchPath("com.itextpdf.samples.signatures.chapter02");
        searchConfig.addPackageToRunnerSearchPath("com.itextpdf.samples.signatures.chapter03");
        searchConfig.addPackageToRunnerSearchPath("com.itextpdf.samples.signatures.chapter04");

        // Samples are run by separate samples runners
        searchConfig.ignorePackageOrClass("com.itextpdf.samples.signatures.chapter02.C2_12_LockFields");
        searchConfig.ignorePackageOrClass("com.itextpdf.samples.signatures.chapter02.C2_10_SequentialSignatures");
        searchConfig.ignorePackageOrClass("com.itextpdf.samples.signatures.chapter02.C2_09_SignatureTypes");
        searchConfig.ignorePackageOrClass("com.itextpdf.samples.signatures.chapter02.C2_11_SignatureWorkflow");
        searchConfig.ignorePackageOrClass("com.itextpdf.samples.signatures.chapter04.C4_07_ClientServerSigning");

        // Samples require a valid certificate which is issued by the service that provides CRL access point
        searchConfig.ignorePackageOrClass("com.itextpdf.samples.signatures.chapter03.C3_02_GetCrlUrl");
        searchConfig.ignorePackageOrClass("com.itextpdf.samples.signatures.chapter03.C3_03_SignWithCRLDefaultImp");
        searchConfig.ignorePackageOrClass("com.itextpdf.samples.signatures.chapter03.C3_04_SignWithCRLOnline");
        searchConfig.ignorePackageOrClass("com.itextpdf.samples.signatures.chapter03.C3_05_SignWithCRLOffline");

        // Samples require a valid certificate which is issued by the service that provides OCSP
        searchConfig.ignorePackageOrClass("com.itextpdf.samples.signatures.chapter03.C3_06_GetOcspUrl");
        searchConfig.ignorePackageOrClass("com.itextpdf.samples.signatures.chapter03.C3_07_SignWithOCSP");

        // Samples require a valid certificate which is issued by the service that provides TSA access point
        searchConfig.ignorePackageOrClass("com.itextpdf.samples.signatures.chapter03.C3_08_GetTsaUrl");
        searchConfig.ignorePackageOrClass("com.itextpdf.samples.signatures.chapter03.C3_09_SignWithTSA");
        searchConfig.ignorePackageOrClass("com.itextpdf.samples.signatures.chapter03.C3_10_SignWithTSAEvent");
        searchConfig.ignorePackageOrClass("com.itextpdf.samples.signatures.chapter03.C3_12_SignWithEstimatedSize");

        // Sample requires USB token
        searchConfig.ignorePackageOrClass("com.itextpdf.samples.signatures.chapter03.C3_11_SignWithToken");

        // Sample requires iKey4000 token and the corresponding dll.
        searchConfig.ignorePackageOrClass("com.itextpdf.samples.signatures.chapter04.C4_02_SignWithPKCS11USB");

        // Sample requires a valid properties file
        searchConfig.ignorePackageOrClass("com.itextpdf.samples.signatures.chapter04.C4_01_SignWithPKCS11HSM");

        // Sample requires a valid BeID dll file
        searchConfig.ignorePackageOrClass("com.itextpdf.samples.signatures.chapter04.C4_03_SignWithPKCS11SC");

        return generateTestsList(searchConfig);
    }

    @Test(timeout = 60000)
    public void test() throws Exception {
        try (FileInputStream license = new FileInputStream(System.getenv("ITEXT7_LICENSEKEY")
                + "/all-products.json")) {
            LicenseKey.loadLicenseFile(license);
        }
        FontCache.clearSavedFonts();
        FontProgramFactory.clearRegisteredFonts();

        runSamples();
        LicenseKey.unloadLicenses();
    }

    @Override
    protected void comparePdf(String outPath, String dest, String cmp) {
        List<Rectangle> ignoredAreas = classAreaMap.get(sampleClass.getName());
        Map<Integer, List<Rectangle>> ignoredAreasMap = new HashMap<>();
        ignoredAreasMap.put(1, ignoredAreas);

        String[] resultFiles = getResultFiles(sampleClass);
        for (int i = 0; i < resultFiles.length; i++) {
            String currentDest = dest + resultFiles[i];
            String currentCmp = cmp + resultFiles[i];
            try {
                addError(new SignatureTestHelper().checkForErrors(currentDest, currentCmp, outPath, ignoredAreasMap));
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
