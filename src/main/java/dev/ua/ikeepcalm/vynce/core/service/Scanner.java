package dev.ua.ikeepcalm.vynce.core.service;


import dev.ua.ikeepcalm.vynce.core.model.ScanConfig;
import dev.ua.ikeepcalm.vynce.core.model.ScanContext;
import dev.ua.ikeepcalm.vynce.core.model.ScanResult;
import dev.ua.ikeepcalm.vynce.core.model.Vulnerability;
import dev.ua.ikeepcalm.vynce.core.model.source.TestType;
import dev.ua.ikeepcalm.vynce.tests.TestFactory;
import dev.ua.ikeepcalm.vynce.tests.VulnerabilityTest;
import dev.ua.ikeepcalm.vynce.ui.ConsoleUI;
import dev.ua.ikeepcalm.vynce.ui.ScanProgress;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

public class Scanner {

    private final List<TestType> testTypes;
    private final ScanConfig config;
    private final ScanContext context;

    public Scanner(String targetUrl, List<TestType> testTypes, int threads) {
        this(targetUrl, testTypes, ScanConfig.builder().threads(threads).build());
    }

    public Scanner(String targetUrl, List<TestType> testTypes, ScanConfig config) {
        this.testTypes = testTypes;
        this.config = config;
        this.context = new ScanContext(targetUrl, config);
    }

    public ScanResult scanWithProgress(ScanProgress progress) {
        ScanResult result = new ScanResult();
        long startTime = System.currentTimeMillis();

        // Initialize crawler first
        ConsoleUI.info("Initializing web crawler...");
        context.initializeCrawler();

        ExecutorService executor = Executors.newFixedThreadPool(config.getThreads());
        List<Future<List<Vulnerability>>> futures = new ArrayList<>();

        try {
            for (TestType testType : testTypes) {
                futures.add(executor.submit(() -> runTest(testType, progress)));
            }

            for (Future<List<Vulnerability>> future : futures) {
                try {
                    result.addVulnerabilities(future.get());
                } catch (Exception e) {
                    ConsoleUI.error("Test execution failed: " + e.getMessage());
                    ConsoleUI.debug("Stack trace: %s", e);
                }
            }

        } finally {
            executor.shutdown();
            progress.complete();
            context.close();
        }

        result.setDuration(System.currentTimeMillis() - startTime);
        result.setTestCount(testTypes.size());

        return result;
    }

    private List<Vulnerability> runTest(TestType testType, ScanProgress progress) {
        progress.update(testType.getDisplayName());

        try {
            VulnerabilityTest testInstance = TestFactory.createTest(testType);
            ConsoleUI.debug("Executing test: " + testType.getDisplayName());

            List<Vulnerability> vulnerabilities = testInstance.execute(context);

            if (!vulnerabilities.isEmpty()) {
                for (Vulnerability vuln : vulnerabilities) {
                    ConsoleUI.vulnerability(testType, vuln.getSeverity(),
                            vuln.getDescription());
                }
            }

            return vulnerabilities;

        } catch (Exception e) {
            ConsoleUI.error("Error running test " + testType + ": " + e.getMessage());
            ConsoleUI.debug("Stack trace: %s", e);
            return new ArrayList<>();
        }
    }
}