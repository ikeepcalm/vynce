package dev.ua.ikeepcalm.vynce.ui.progress;


public interface ProgressCallback {

    void onTestStart(String testName, int totalSteps);

    void onProgress(String testName, int current, int total, String detail);

    void onTestComplete(String testName, int vulnerabilitiesFound);

    void onVulnerabilityFound(String testName, String severity, String description);
}
