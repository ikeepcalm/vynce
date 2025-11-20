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
import lombok.Getter;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorCompletionService;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

public class Scanner {

    private final List<TestType> testTypes;
    private final ScanConfig config;

    @Getter
    private final ScanContext context;

    private volatile boolean stopping = false;
    private ExecutorService executor;
    private IntermediateResultsSaver resultsSaver;
    private ScanResult currentResult;

    public Scanner(String targetUrl, List<TestType> testTypes, int threads) {
        this(targetUrl, testTypes, ScanConfig.builder().threads(threads).build());
    }

    public Scanner(String targetUrl, List<TestType> testTypes, ScanConfig config) {
        this.testTypes = testTypes;
        this.config = config;
        this.context = new ScanContext(targetUrl, config);
    }


    public void stop() {
        stopping = true;
        if (executor != null && !executor.isShutdown()) {
            executor.shutdownNow();
        }
    }

    /**
     * Get the current scan results (useful for partial results when scan is interrupted).
     * @return The current ScanResult, or null if scan hasn't started
     */
    public ScanResult getPartialResults() {
        if (currentResult != null) {
            // Set duration up to current point
            currentResult.setDuration(System.currentTimeMillis() -
                (currentResult.getDuration() == 0 ? System.currentTimeMillis() :
                 System.currentTimeMillis() - currentResult.getDuration()));
        }
        return currentResult;
    }

    public ScanResult scanWithProgress(ScanProgress progress) {
        ScanResult result = new ScanResult();
        this.currentResult = result; // Store reference for partial results
        long startTime = System.currentTimeMillis();

        if (stopping) {
            ConsoleUI.warning("Scan stopped before starting");
            return result;
        }


        ConsoleUI.debug("Initializing web crawler...");
        context.initializeCrawler();


        progress.start();


        resultsSaver = new IntermediateResultsSaver(result);
        resultsSaver.start();

        executor = Executors.newFixedThreadPool(config.getThreads());
        ExecutorCompletionService<TestResult> completionService =
                new ExecutorCompletionService<>(executor);

        try {

            for (TestType testType : testTypes) {
                if (stopping) break;
                completionService.submit(() -> {
                    List<Vulnerability> vulns = runTest(testType, progress, result);
                    return new TestResult(testType, vulns);
                });
            }


            int tasksSubmitted = testTypes.size();
            for (int i = 0; i < tasksSubmitted; i++) {
                if (stopping) break;
                try {
                    Future<TestResult> future = completionService.take();
                    TestResult testResult = future.get();


                    progress.update(testResult.testType.getDisplayName());


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


            if (!vulnerabilities.isEmpty() && ConsoleUI.isVerbose()) {
                for (Vulnerability vuln : vulnerabilities) {

                    if (vuln.severity() == Severity.CRITICAL) {
                        ConsoleUI.error("⚠️  CRITICAL VULNERABILITY FOUND!");
                        ConsoleUI.vulnerability(testType, vuln.severity(),
                                vuln.description());
                        ConsoleUI.error("Location: " + vuln.url());
                    } else {
                        ConsoleUI.vulnerability(testType, vuln.severity(),
                                vuln.description());
                    }
                }
            }


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


    private record TestResult(TestType testType, List<Vulnerability> vulnerabilities) {
    }
}