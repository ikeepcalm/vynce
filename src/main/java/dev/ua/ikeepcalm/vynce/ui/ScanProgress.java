package dev.ua.ikeepcalm.vynce.ui;

import me.tongfei.progressbar.ProgressBar;
import me.tongfei.progressbar.ProgressBarBuilder;
import me.tongfei.progressbar.ProgressBarStyle;

public class ScanProgress {

    private ProgressBar progressBar;
    private int totalTests;
    private int completed;
    private volatile int vulnerabilitiesFound = 0;

    public ScanProgress(int totalTests) {
        this.totalTests = totalTests;
        this.completed = 0;

        this.progressBar = new ProgressBarBuilder()
                .setTaskName("Scanning")
                .setInitialMax(totalTests)
                .setStyle(ProgressBarStyle.ASCII)
                .setUpdateIntervalMillis(100)
                .showSpeed()
                .build();
    }

    public void update(String testName) {
        progressBar.step();
        updateMessage(testName);
        completed++;
    }

    /**
     * FR-9: Update vulnerability count in real-time
     */
    public void updateVulnerabilityCount(int count) {
        this.vulnerabilitiesFound = count;
        updateMessage(progressBar.getExtraMessage());
    }

    private void updateMessage(String testName) {
        int percentage = (int) ((completed * 100.0) / totalTests);
        String message = String.format("%s | %d%% | Found: %d",
            testName, percentage, vulnerabilitiesFound);
        progressBar.setExtraMessage(message);
    }

    public void complete() {
        progressBar.close();
        ConsoleUI.success("Scan completed! (" + completed + "/" + totalTests + " tests, " +
                         vulnerabilitiesFound + " vulnerabilities found)");
    }
}