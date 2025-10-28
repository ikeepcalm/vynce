package dev.ua.ikeepcalm.vynce.core;


import dev.ua.ikeepcalm.vynce.core.source.Severity;
import dev.ua.ikeepcalm.vynce.core.source.Test;
import dev.ua.ikeepcalm.vynce.ui.ConsoleUI;
import dev.ua.ikeepcalm.vynce.ui.ScanProgress;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.ThreadLocalRandom;

public class Scanner {

    private final String targetUrl;
    private final List<Test> tests;
    private final int threads;

    public Scanner(String targetUrl, List<Test> tests, int threads) {
        this.targetUrl = targetUrl;
        this.tests = tests;
        this.threads = threads;
    }

    public ScanResult scanWithProgress(ScanProgress progress) {
        ScanResult result = new ScanResult();
        long startTime = System.currentTimeMillis();

        ExecutorService executor = Executors.newFixedThreadPool(threads);
        List<Future<List<Vulnerability>>> futures = new ArrayList<>();

        for (Test test : tests) {
            futures.add(executor.submit(() -> runTest(test, progress)));
        }

        for (Future<List<Vulnerability>> future : futures) {
            try {
                result.addVulnerabilities(future.get());
            } catch (Exception e) {
                ConsoleUI.error("Test failed: " + e.getMessage());
            }
        }

        executor.shutdown();
        progress.complete();

        result.setDuration(System.currentTimeMillis() - startTime);
        result.setTestCount(tests.size());

        return result;
    }

    private List<Vulnerability> runTest(Test test, ScanProgress progress) {
        progress.update(test.getDisplayName());

        try {
            Thread.sleep(ThreadLocalRandom.current().nextInt(500, 2000));
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        // Stub: randomly generate vulnerabilities for demo
        List<Vulnerability> vulnerabilities = new ArrayList<>();

        if (Math.random() < 0.3) { // 30% chance of finding vulnerability
            Severity severity = selectRandomSeverity();
            vulnerabilities.add(new Vulnerability(test,
                    severity,
                    "Potential " + test.getDisplayName() + " vulnerability detected at " + targetUrl,
                    targetUrl + "/vulnerable-endpoint"
            ));

            ConsoleUI.vulnerability(test, severity,
                    "Vulnerability detected in " + test.getDisplayName() + " test");
        }

        return vulnerabilities;
    }

    private Severity selectRandomSeverity() {
        Severity[] severities = (Severity.values());
        return severities[ThreadLocalRandom.current().nextInt(severities.length)];
    }
}