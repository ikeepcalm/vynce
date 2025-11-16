package dev.ua.ikeepcalm.vynce.core.service;

import dev.ua.ikeepcalm.vynce.core.model.ScanResult;
import dev.ua.ikeepcalm.vynce.report.JsonReportGenerator;
import dev.ua.ikeepcalm.vynce.report.ReportGenerator;
import dev.ua.ikeepcalm.vynce.ui.ConsoleUI;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Timer;
import java.util.TimerTask;

/**
 * NFR-4: Saves intermediate scan results every 2 minutes or after each test completion.
 * This ensures data is not lost in case of interruption.
 */
public class IntermediateResultsSaver {

    private static final long SAVE_INTERVAL_MS = 2 * 60 * 1000; // 2 minutes
    private static final String TEMP_DIR = ".vynce-temp";

    private final ScanResult result;
    private final Timer timer;
    private final Path saveDirectory;
    private final ReportGenerator generator;
    private volatile boolean stopped = false;

    public IntermediateResultsSaver(ScanResult result) {
        this.result = result;
        this.timer = new Timer("IntermediateResultsSaver", true);
        this.generator = new JsonReportGenerator();
        this.saveDirectory = createTempDirectory();
    }

    /**
     * Start periodic saving of intermediate results
     */
    public void start() {
        if (saveDirectory == null) {
            ConsoleUI.debug("Intermediate results saving disabled (could not create temp directory)");
            return;
        }

        // Schedule periodic saves every 2 minutes
        timer.scheduleAtFixedRate(new TimerTask() {
            @Override
            public void run() {
                if (!stopped) {
                    saveIntermediateResults();
                }
            }
        }, SAVE_INTERVAL_MS, SAVE_INTERVAL_MS);

        ConsoleUI.debug("Intermediate results saver started (saving every 2 minutes)");
    }

    /**
     * Save results after completing a test module
     */
    public void saveAfterTest() {
        if (!stopped && saveDirectory != null) {
            saveIntermediateResults();
        }
    }

    /**
     * Stop the saver and clean up
     */
    public void stop() {
        stopped = true;
        timer.cancel();
        cleanupTempFiles();
    }

    /**
     * Save current scan results to a temporary file
     */
    private void saveIntermediateResults() {
        if (result.getVulnerabilities().isEmpty()) {
            return; // Nothing to save yet
        }

        try {
            String timestamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMdd_HHmmss"));
            String filename = "vynce_intermediate_" + timestamp + ".json";
            Path filePath = saveDirectory.resolve(filename);

            String reportContent = generator.generate(result);
            Files.writeString(filePath, reportContent);

            ConsoleUI.debug("Saved intermediate results to: " + filePath.getFileName());

            // Keep only the last 3 intermediate files to save space
            cleanupOldFiles();

        } catch (IOException e) {
            ConsoleUI.debug("Failed to save intermediate results: " + e.getMessage());
        }
    }

    /**
     * Create temporary directory for intermediate results
     */
    private Path createTempDirectory() {
        try {
            Path tempDir = Paths.get(System.getProperty("user.home"), TEMP_DIR);
            if (!Files.exists(tempDir)) {
                Files.createDirectories(tempDir);
            }
            return tempDir;
        } catch (IOException e) {
            ConsoleUI.debug("Could not create temp directory: " + e.getMessage());
            return null;
        }
    }

    /**
     * Clean up old intermediate files, keeping only the last 3
     */
    private void cleanupOldFiles() {
        try {
            Files.list(saveDirectory)
                .filter(p -> p.getFileName().toString().startsWith("vynce_intermediate_"))
                .sorted((p1, p2) -> p2.getFileName().toString().compareTo(p1.getFileName().toString()))
                .skip(3) // Keep the 3 most recent
                .forEach(path -> {
                    try {
                        Files.deleteIfExists(path);
                        ConsoleUI.debug("Cleaned up old intermediate file: " + path.getFileName());
                    } catch (IOException e) {
                        // Ignore cleanup errors
                    }
                });
        } catch (IOException e) {
            // Ignore cleanup errors
        }
    }

    /**
     * Clean up all temporary files on normal completion
     */
    private void cleanupTempFiles() {
        if (saveDirectory == null) {
            return;
        }

        try {
            Files.list(saveDirectory)
                .filter(p -> p.getFileName().toString().startsWith("vynce_intermediate_"))
                .forEach(path -> {
                    try {
                        Files.deleteIfExists(path);
                    } catch (IOException e) {
                        // Ignore cleanup errors
                    }
                });
            ConsoleUI.debug("Cleaned up all intermediate result files");
        } catch (IOException e) {
            // Ignore cleanup errors
        }
    }

    /**
     * Get the path to the most recent intermediate results file
     */
    public Path getMostRecentIntermediateFile() {
        if (saveDirectory == null) {
            return null;
        }

        try {
            return Files.list(saveDirectory)
                .filter(p -> p.getFileName().toString().startsWith("vynce_intermediate_"))
                .max((p1, p2) -> p1.getFileName().toString().compareTo(p2.getFileName().toString()))
                .orElse(null);
        } catch (IOException e) {
            return null;
        }
    }
}
