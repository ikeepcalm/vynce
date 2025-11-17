package dev.ua.ikeepcalm.vynce.ui;

import me.tongfei.progressbar.ProgressBar;
import me.tongfei.progressbar.ProgressBarBuilder;
import me.tongfei.progressbar.ProgressBarStyle;
import me.tongfei.progressbar.ConsoleProgressBarConsumer;

import static org.fusesource.jansi.Ansi.Color;

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
                .setTaskName("Scanning")
                .setInitialMax(totalTests)
                .setStyle(ProgressBarStyle.ASCII)
                .setUpdateIntervalMillis(20)
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
        int percentage = (int) ((completed * 100.0) / totalTests);

        // Add colors to the message using ANSI codes
        String coloredMessage = String.format(" \u001B[36m%s\u001B[0m | \u001B[33m%d%%\u001B[0m | Found: \u001B[32m%d\u001B[0m",
                currentTestName, percentage, vulnerabilitiesFound);

        progressBar.setExtraMessage(coloredMessage);
    }

    public void complete() {
        if (progressBar != null) {
            progressBar.close();
        }
        ConsoleUI.success("Scan completed! (" + completed + "/" + totalTests + " tests, " +
                         vulnerabilitiesFound + " vulnerabilities found)");
    }
}