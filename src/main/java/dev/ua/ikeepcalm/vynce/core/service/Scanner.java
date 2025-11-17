package dev.ua.ikeepcalm.vynce.core.service;


import dev.ua.ikeepcalm.vynce.core.model.ScanConfig;
import dev.ua.ikeepcalm.vynce.core.model.ScanContext;
import dev.ua.ikeepcalm.vynce.core.model.ScanResult;
import dev.ua.ikeepcalm.vynce.core.model.Vulnerability;
import dev.ua.ikeepcalm.vynce.core.model.source.Severity;
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
import java.util.concurrent.ExecutorCompletionService;

public class Scanner {

    private final List<TestType> testTypes;
    private final ScanConfig config;
    private final ScanContext context;
    private volatile boolean stopping = false;
    private ExecutorService executor;
    private IntermediateResultsSaver resultsSaver;

    public Scanner(String targetUrl, List<TestType> testTypes, int threads) {
        this(targetUrl, testTypes, ScanConfig.builder().threads(threads).build());
    }

    public Scanner(String targetUrl, List<TestType> testTypes, ScanConfig config) {
        this.testTypes = testTypes;
        this.config = config;
        this.context = new ScanContext(targetUrl, config);
    }

    /**
     * Stop the scan gracefully
     */
    public void stop() {
        stopping = true;
        if (executor != null && !executor.isShutdown()) {
            executor.shutdownNow();
        }
    }

    public ScanResult scanWithProgress(ScanProgress progress) {
        ScanResult result = new ScanResult();
        long startTime = System.currentTimeMillis();

        if (stopping) {
            ConsoleUI.warning("Scan stopped before starting");
            return result;
        }

        // Initialize crawler first
        ConsoleUI.info("Initializing web crawler...");
        context.initializeCrawler();

        // NFR-4: Start intermediate results saver
        resultsSaver = new IntermediateResultsSaver(result);
        resultsSaver.start();

        executor = Executors.newFixedThreadPool(config.getThreads());
        ExecutorCompletionService<TestResult> completionService =
            new ExecutorCompletionService<>(executor);

        try {
            // Submit all tests
            for (TestType testType : testTypes) {
                if (stopping) break;
                completionService.submit(() -> {
                    List<Vulnerability> vulns = runTest(testType, progress, result);
                    return new TestResult(testType, vulns);
                });
            }

            // Process results as they complete
            int tasksSubmitted = testTypes.size();
            for (int i = 0; i < tasksSubmitted; i++) {
                if (stopping) break;
                try {
                    Future<TestResult> future = completionService.take(); // Blocks until next result
                    TestResult testResult = future.get();

                    // Update progress when test completes
                    progress.update(testResult.testType.getDisplayName());

                    // Add vulnerabilities to result
                    result.addVulnerabilities(testResult.vulnerabilities);
                    progress.updateVulnerabilityCount(result.getVulnerabilities().size());
                } catch (Exception e) {
                    if (!stopping) {
                        ConsoleUI.error("Test execution failed: " + e.getMessage());
                        ConsoleUI.debug("Stack trace: %s", e);
                    }
                }
            }

        } finally {
            // NFR-4: Stop intermediate results saver and cleanup temp files
            if (resultsSaver != null) {
                resultsSaver.stop();
            }
            executor.shutdown();
            progress.complete();
            context.close();
        }

        result.setDuration(System.currentTimeMillis() - startTime);
        result.setTestCount(testTypes.size());

        return result;
    }

    private List<Vulnerability> runTest(TestType testType, ScanProgress progress, ScanResult result) {
        if (stopping) {
            return new ArrayList<>();
        }

        try {
            VulnerabilityTest testInstance = TestFactory.createTest(testType);
            ConsoleUI.debug("Executing test: " + testType.getDisplayName());

            List<Vulnerability> vulnerabilities = testInstance.execute(context);

            // Only print vulnerabilities during scan if in verbose mode
            // Otherwise, they'll be displayed in the final results section
            if (!vulnerabilities.isEmpty() && ConsoleUI.isVerbose()) {
                for (Vulnerability vuln : vulnerabilities) {
                    // FR-10: Immediate notification of critical vulnerabilities
                    if (vuln.getSeverity() == Severity.CRITICAL) {
                        ConsoleUI.error("⚠️  CRITICAL VULNERABILITY FOUND!");
                        ConsoleUI.vulnerability(testType, vuln.getSeverity(),
                                vuln.getDescription());
                        ConsoleUI.error("Location: " + vuln.getUrl());
                    } else {
                        ConsoleUI.vulnerability(testType, vuln.getSeverity(),
                                vuln.getDescription());
                    }
                }
            }

            // NFR-4: Save intermediate results after each test completion
            if (resultsSaver != null) {
                resultsSaver.saveAfterTest();
            }

            return vulnerabilities;

        } catch (Exception e) {
            if (!stopping) {
                ConsoleUI.error("Error running test " + testType + ": " + e.getMessage());
                ConsoleUI.debug("Stack trace: %s", e);
            }
            return new ArrayList<>();
        }
    }

    /**
     * Helper class to hold test results
     */
    private static class TestResult {
        final TestType testType;
        final List<Vulnerability> vulnerabilities;

        TestResult(TestType testType, List<Vulnerability> vulnerabilities) {
            this.testType = testType;
            this.vulnerabilities = vulnerabilities;
        }
    }
}