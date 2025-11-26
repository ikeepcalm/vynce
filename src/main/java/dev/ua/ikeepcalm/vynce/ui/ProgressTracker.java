package dev.ua.ikeepcalm.vynce.ui;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class ProgressTracker {

    private static final char[] SPINNER_FRAMES = {'/', '-', '\\', '|'};
    private final String testName;
    private int current;
    private int total;
    private String detail;
    private boolean completed;
    private int vulnerabilitiesFound;
    private long startTime;
    private int spinnerIndex;

    public ProgressTracker(String testName, int total) {
        this.testName = testName;
        this.total = total;
        this.current = 0;
        this.detail = "";
        this.completed = false;
        this.vulnerabilitiesFound = 0;
        this.startTime = System.currentTimeMillis();
        this.spinnerIndex = 0;
    }

    public char getSpinnerChar() {
        return SPINNER_FRAMES[spinnerIndex % SPINNER_FRAMES.length];
    }

    public void advanceSpinner() {
        spinnerIndex++;
    }

    public int getProgressPercentage() {
        if (total == 0) return 0;
        return (int) ((double) current / total * 100);
    }

    public long getElapsedSeconds() {
        return (System.currentTimeMillis() - startTime) / 1000;
    }

    public void updateProgress(int current, int total, String detail) {
        this.current = current;
        if (total > 0) {
            this.total = total;
        }
        this.detail = detail != null ? detail : "";
    }

    public void markCompleted(int vulnerabilitiesFound) {
        this.completed = true;
        this.vulnerabilitiesFound = vulnerabilitiesFound;
        this.current = this.total;
    }
}
