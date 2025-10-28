package dev.ua.ikeepcalm.vynce.ui;

import me.tongfei.progressbar.ProgressBar;
import me.tongfei.progressbar.ProgressBarBuilder;
import me.tongfei.progressbar.ProgressBarStyle;

public class ScanProgress {

    private ProgressBar progressBar;
    private int totalTests;
    private int completed;

    public ScanProgress(int totalTests) {
        this.totalTests = totalTests;
        this.completed = 0;

        this.progressBar = new ProgressBarBuilder()
                .setTaskName("Scanning")
                .setInitialMax(totalTests)
                .setStyle(ProgressBarStyle.COLORFUL_UNICODE_BLOCK)
                .setUpdateIntervalMillis(100)
                .showSpeed()
                .build();
    }

    public void update(String testName) {
        progressBar.step();
        progressBar.setExtraMessage(testName);
        completed++;
    }

    public void complete() {
        progressBar.close();
        ConsoleUI.success("Scan completed! (" + completed + "/" + totalTests + " tests)");
    }
}