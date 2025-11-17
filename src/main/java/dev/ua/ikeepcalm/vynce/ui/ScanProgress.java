package dev.ua.ikeepcalm.vynce.ui;

import me.tongfei.progressbar.ProgressBar;
import me.tongfei.progressbar.ProgressBarBuilder;
import me.tongfei.progressbar.ProgressBarStyle;

import java.time.temporal.ChronoUnit;

public class ScanProgress {

    private ProgressBar progressBar;
    private int totalTests;
    private int completed;
    private volatile int vulnerabilitiesFound = 0;
    private String currentTestName = "";

    public ScanProgress(int totalTests) {
        this.totalTests = totalTests;
        this.completed = 0;
    }

    /**
     * Start the progress bar display (call this after crawler completes)
     */
    public void start() {
        this.progressBar = new ProgressBarBuilder()
                .setTaskName("\u001B[32mScanning\u001B[0m") // Green "Scanning"
                .setInitialMax(totalTests)
                .setStyle(ProgressBarStyle.ASCII)
                .setUpdateIntervalMillis(20)
                .hideEta()
                .showSpeed()
                .build();
    }

    public void update(String testName) {
        this.currentTestName = testName;
        progressBar.step();
        updateMessage();
        completed++;
    }

    /**
     * FR-9: Update vulnerability count in real-time
     */
    public void updateVulnerabilityCount(int count) {
        this.vulnerabilitiesFound = count;
        updateMessage();
    }

    private void updateMessage() {
        String message = String.format(" %s | Found: %d", currentTestName, vulnerabilitiesFound);
        progressBar.setExtraMessage(message);
    }

    public void complete() {
        if (progressBar != null) {
            progressBar.close();
        }
        ConsoleUI.success("Scan completed! (" + completed + "/" + totalTests + " tests, " +
                         vulnerabilitiesFound + " vulnerabilities found)");
    }
}