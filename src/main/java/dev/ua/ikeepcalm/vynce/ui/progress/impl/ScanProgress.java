package dev.ua.ikeepcalm.vynce.ui.progress.impl;

import dev.ua.ikeepcalm.vynce.ui.ConsoleUI;
import dev.ua.ikeepcalm.vynce.ui.ProgressTracker;
import dev.ua.ikeepcalm.vynce.ui.progress.ProgressCallback;
import org.fusesource.jansi.Ansi;

import java.io.PrintStream;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.fusesource.jansi.Ansi.Color.*;
import static org.fusesource.jansi.Ansi.ansi;

public class ScanProgress implements ProgressCallback {

    private static final boolean KEEP_COMPLETED_TESTS = true;
    private static final int NOTIFICATION_TIMEOUT_MS = 10000;
    private static final int REFRESH_INTERVAL_MS = 100;
    private static final int PROGRESS_BAR_WIDTH = 50;

    private final Map<String, ProgressTracker> activeTests = new ConcurrentHashMap<>();
    private final Map<String, ProgressTracker> completedTests = new ConcurrentHashMap<>();
    private final Queue<VulnerabilityNotification> recentNotifications = new LinkedList<>();

    private final int totalTests;
    private final boolean verbose;

    private final AtomicInteger completedCount = new AtomicInteger(0);
    private final AtomicInteger totalVulnerabilities = new AtomicInteger(0);

    private final PrintStream out;

    private ScheduledExecutorService refreshExecutor;
    private volatile boolean running = false;

    public ScanProgress(int totalTests) {
        this(totalTests, false, System.out);
    }

    public ScanProgress(int totalTests, boolean verbose) {
        this(totalTests, verbose, System.out);
    }

    public ScanProgress(int totalTests, boolean verbose, PrintStream out) {
        this.totalTests = totalTests;
        this.verbose = verbose;
        this.out = out;
    }

    public void start() {
        running = true;

        if (verbose) {
            ConsoleUI.info("Starting vulnerability scan...");
            return;
        }

        refreshExecutor = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "ProgressDisplay-Refresh");
            t.setDaemon(true);
            return t;
        });

        refreshExecutor.scheduleAtFixedRate(
                this::render,
                0,
                REFRESH_INTERVAL_MS,
                TimeUnit.MILLISECONDS
        );
    }

    public void stop() {
        running = false;

        if (verbose) {
            out.println();
            ConsoleUI.success("Scan completed! (" + completedCount.get() + "/" + totalTests +
                              " tests, " + totalVulnerabilities.get() + " vulnerabilities found)");
            return;
        }

        if (refreshExecutor != null) {
            refreshExecutor.shutdown();
            try {
                refreshExecutor.awaitTermination(1, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }

        render();

        out.println(ansi().fg(CYAN).a("═".repeat(100)).reset());
        out.println();
        ConsoleUI.success("Scan completed! (" + completedCount.get() + "/" + totalTests +
                          " tests, " + totalVulnerabilities.get() + " vulnerabilities found)");
    }

    private synchronized void render() {
        if (!running) return;

        StringBuilder display = new StringBuilder();

        display.append("\u001B[2J");
        display.append("\u001B[H");

        display.append(ansi().fg(CYAN).a("═".repeat(100)).reset()).append("\n");
        display.append(ansi().fg(YELLOW).a("           VULNERABILITY SCAN PROGRESS").reset()).append("\n");
        display.append(ansi().fg(CYAN).a("═".repeat(100)).reset()).append("\n");

        List<ProgressTracker> activeList = new ArrayList<>(activeTests.values());
        activeList.sort(Comparator.comparing(ProgressTracker::getTestName));

        for (ProgressTracker tracker : activeList) {
            tracker.advanceSpinner();
            display.append(renderTestProgress(tracker, false)).append("\n");
        }

        if (KEEP_COMPLETED_TESTS) {
            List<ProgressTracker> completedList = new ArrayList<>(completedTests.values());
            completedList.sort(Comparator.comparing(ProgressTracker::getTestName));

            for (ProgressTracker tracker : completedList) {
                display.append(renderTestProgress(tracker, true)).append("\n");
            }
        }

        cleanupOldNotifications();

        if (!recentNotifications.isEmpty()) {
            display.append(ansi().fg(CYAN).a("─".repeat(100)).reset()).append("\n");
            display.append(renderNotificationArea()).append("\n");
        }

        display.append(ansi().fg(CYAN).a("─".repeat(100)).reset()).append("\n");

        display.append(renderGlobalProgress());

        out.print(display);
        out.flush();

    }

    private String renderTestProgress(ProgressTracker tracker, boolean isCompleted) {
        StringBuilder line = new StringBuilder();

        String testName = tracker.getTestName();
        if (testName.length() > 20) {
            testName = testName.substring(0, 17) + "...";
        }
        testName = String.format("%-20s", testName);

        if (isCompleted) {
            line.append(ansi().fg(GREEN).a(testName).a(" [DONE]").reset());
        } else {
            line.append(ansi().fg(YELLOW).a(testName).a(" [").a(tracker.getSpinnerChar()).a("]").reset());
        }

        int percentage = tracker.getProgressPercentage();
        line.append(String.format(" %3d%% ", percentage));

        line.append(renderProgressBar(percentage, isCompleted));

        line.append(String.format(" %d/%d", tracker.getCurrent(), tracker.getTotal()));

        if (tracker.getVulnerabilitiesFound() > 0) {
            line.append(ansi().fg(RED).a(" [").a(tracker.getVulnerabilitiesFound()).a("]").reset());
        }

        return line.toString();
    }

    private String renderProgressBar(int percentage, boolean isCompleted) {
        int filled = (int) (PROGRESS_BAR_WIDTH * percentage / 100.0);
        int empty = PROGRESS_BAR_WIDTH - filled;

        Ansi.Color color = isCompleted ? GREEN : BLUE;

        return ansi()
                .fg(color)
                .a("[")
                .a("=".repeat(Math.max(0, filled)))
                .a(filled > 0 && empty > 0 ? ">" : "")
                .a(" ".repeat(Math.max(0, empty - (filled > 0 ? 1 : 0))))
                .a("]")
                .reset()
                .toString();
    }

    private String renderNotificationArea() {
        if (recentNotifications.isEmpty()) {
            return "";
        }

        VulnerabilityNotification latest = ((LinkedList<VulnerabilityNotification>) recentNotifications).getLast();

        StringBuilder line = new StringBuilder();
        line.append(ansi().fg(MAGENTA).a("[!] Latest: ").reset());

        String message = String.format("[%s] %s", latest.severity, latest.description);
        if (message.length() > 70) {
            message = message.substring(0, 67) + "...";
        }

        line.append(message);

        return line.toString();
    }

    private String renderGlobalProgress() {
        int completed = completedCount.get();
        int percentage = totalTests == 0 ? 0 : (completed * 100 / totalTests);

        return ansi().fg(GREEN).a("Overall ").reset() +
               String.format("%3d%% ", percentage) +
               renderProgressBar(percentage, completed == totalTests) +
               String.format(" %d/%d tests", completed, totalTests) +
               ansi().fg(YELLOW).a(" | ").reset() +
               String.format("Vulnerabilities: %d", totalVulnerabilities.get());
    }

    private void cleanupOldNotifications() {
        long currentTime = System.currentTimeMillis();
        recentNotifications.removeIf(n -> currentTime - n.timestamp > NOTIFICATION_TIMEOUT_MS);
    }

    @Override
    public synchronized void onTestStart(String testName, int totalSteps) {
        if (activeTests.containsKey(testName)) {
            ConsoleUI.debug("WARNING: Test '" + testName + "' already active, ignoring duplicate start");
            return;
        }
        if (completedTests.containsKey(testName)) {
            ConsoleUI.debug("WARNING: Test '" + testName + "' already completed, ignoring duplicate start");
            return;
        }

        ConsoleUI.debug("Starting test: " + testName + " with " + totalSteps + " steps");
        ProgressTracker tracker = new ProgressTracker(testName, totalSteps);
        activeTests.put(testName, tracker);

        if (verbose) {
            ConsoleUI.info("Starting test: " + testName + " (" + totalSteps + " checks)");
        }
    }

    @Override
    public synchronized void onProgress(String testName, int current, int total, String detail) {
        ProgressTracker tracker = activeTests.get(testName);
        if (tracker != null) {
            tracker.updateProgress(current, total, detail);
        }
    }

    @Override
    public synchronized void onTestComplete(String testName, int vulnerabilitiesFound) {
        if (completedTests.containsKey(testName)) {
            return;
        }

        ProgressTracker tracker = activeTests.remove(testName);
        if (tracker != null) {
            tracker.markCompleted(vulnerabilitiesFound);
            completedTests.put(testName, tracker);
            completedCount.incrementAndGet();

            if (verbose) {
                String vulnMessage = vulnerabilitiesFound > 0
                        ? " - Found " + vulnerabilitiesFound + " vulnerability/vulnerabilities"
                        : " - No vulnerabilities found";
                ConsoleUI.success("Completed test: " + testName + vulnMessage);
            }
        }
    }

    @Override
    public synchronized void onVulnerabilityFound(String testName, String severity, String description) {
        totalVulnerabilities.incrementAndGet();

        ProgressTracker tracker = activeTests.get(testName);
        if (tracker != null) {
            tracker.setVulnerabilitiesFound(tracker.getVulnerabilitiesFound() + 1);
        }

        if (verbose) {
            ConsoleUI.warning("Vulnerability found: [" + severity + "] " +
                              (description.length() > 60 ? description.substring(0, 57) + "..." : description));
        }

        recentNotifications.add(new VulnerabilityNotification(severity, description));

        while (recentNotifications.size() > 5) {
            recentNotifications.poll();
        }
    }

    private static class VulnerabilityNotification {
        final String severity;
        final String description;
        final long timestamp;

        VulnerabilityNotification(String severity, String description) {
            this.severity = severity;
            this.description = description;
            this.timestamp = System.currentTimeMillis();
        }
    }
}
