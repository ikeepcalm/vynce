package dev.ua.ikeepcalm.vynce.report;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import dev.ua.ikeepcalm.vynce.core.model.ScanResult;
import dev.ua.ikeepcalm.vynce.ui.ConsoleUI;
import lombok.Getter;
import lombok.Setter;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.stream.Stream;


public class ReportManager {

    private static final String VYNCE_DIR = ".vynce";
    private static final String REPORTS_DIR = "reports";
    private static final String EXPORTS_DIR = "exports";
    private static final DateTimeFormatter TIMESTAMP_FORMAT = DateTimeFormatter.ofPattern("yyyyMMdd_HHmmss");


    @Getter
    private final Path reportsDirectory;

    @Getter
    private final Path exportsDirectory;
    private final ObjectMapper objectMapper;

    public ReportManager() {
        this.objectMapper = new ObjectMapper();
        this.objectMapper.registerModule(new JavaTimeModule());
        this.objectMapper.disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
        this.reportsDirectory = initializeReportsDirectory();
        this.exportsDirectory = initializeExportsDirectory();
    }


    private Path initializeReportsDirectory() {
        try {
            Path vynceDir = Paths.get(System.getProperty("user.home"), VYNCE_DIR);
            Path reportsDir = vynceDir.resolve(REPORTS_DIR);

            if (!Files.exists(reportsDir)) {
                Files.createDirectories(reportsDir);
                ConsoleUI.debug("Created reports directory: " + reportsDir);
            }

            return reportsDir;
        } catch (IOException e) {
            ConsoleUI.error("Failed to create reports directory: " + e.getMessage());
            return null;
        }
    }


    private Path initializeExportsDirectory() {
        try {
            Path vynceDir = Paths.get(System.getProperty("user.home"), VYNCE_DIR);
            Path exportsDir = vynceDir.resolve(EXPORTS_DIR);

            if (!Files.exists(exportsDir)) {
                Files.createDirectories(exportsDir);
                ConsoleUI.debug("Created exports directory: " + exportsDir);
            }

            return exportsDir;
        } catch (IOException e) {
            ConsoleUI.error("Failed to create exports directory: " + e.getMessage());
            return null;
        }
    }


    public String saveReport(ScanResult result, String targetUrl) {
        if (reportsDirectory == null) {
            ConsoleUI.error("Reports directory not available");
            return null;
        }

        try {
            String reportId = LocalDateTime.now().format(TIMESTAMP_FORMAT);

            ReportMetadata metadata = new ReportMetadata(
                    reportId,
                    targetUrl,
                    LocalDateTime.now(),
                    result.getVulnerabilities().size(),
                    result.getCriticalCount(),
                    result.getHighCount(),
                    result.getMediumCount(),
                    result.getLowCount(),
                    result.getDuration()
            );

            Path metadataPath = reportsDirectory.resolve(reportId + "_metadata.json");
            objectMapper.writerWithDefaultPrettyPrinter().writeValue(metadataPath.toFile(), metadata);

            Path resultPath = reportsDirectory.resolve(reportId + "_result.json");
            objectMapper.writerWithDefaultPrettyPrinter().writeValue(resultPath.toFile(), result);

            ConsoleUI.debug("Saved report with ID: " + LocalDateTime.now().format(TIMESTAMP_FORMAT));
            return LocalDateTime.now().format(TIMESTAMP_FORMAT);

        } catch (IOException e) {
            ConsoleUI.error("Failed to save report: " + e.getMessage());
            return null;
        }
    }

    public List<ReportMetadata> listReports() {
        if (reportsDirectory == null) {
            return new ArrayList<>();
        }

        List<ReportMetadata> reports = new ArrayList<>();

        try (Stream<Path> files = Files.list(reportsDirectory)) {
            files.filter(p -> p.getFileName().toString().endsWith("_metadata.json"))
                    .forEach(metadataFile -> {
                        try {
                            ReportMetadata metadata = objectMapper.readValue(
                                    metadataFile.toFile(),
                                    ReportMetadata.class
                            );
                            reports.add(metadata);
                        } catch (IOException e) {
                            ConsoleUI.debug("Failed to read metadata: " + metadataFile);
                        }
                    });

            reports.sort(Comparator.comparing(ReportMetadata::getTimestamp).reversed());

        } catch (IOException e) {
            ConsoleUI.error("Failed to list reports: " + e.getMessage());
        }

        return reports;
    }

    public ScanResult loadReport(String reportId) {
        if (reportsDirectory == null) {
            return null;
        }

        try {
            Path resultPath = reportsDirectory.resolve(reportId + "_result.json");

            if (!Files.exists(resultPath)) {
                ConsoleUI.error("Report not found: " + reportId);
                return null;
            }

            return objectMapper.readValue(resultPath.toFile(), ScanResult.class);

        } catch (IOException e) {
            ConsoleUI.error("Failed to load report: " + e.getMessage());
            return null;
        }
    }

    public ReportMetadata getReportMetadata(String reportId) {
        if (reportsDirectory == null) {
            return null;
        }

        try {
            Path metadataPath = reportsDirectory.resolve(reportId + "_metadata.json");

            if (!Files.exists(metadataPath)) {
                return null;
            }

            return objectMapper.readValue(metadataPath.toFile(), ReportMetadata.class);

        } catch (IOException e) {
            ConsoleUI.debug("Failed to load metadata for: " + reportId);
            return null;
        }
    }

    public boolean exportReport(String reportId, String outputPath, String format) {
        ScanResult result = loadReport(reportId);
        if (result == null) {
            return false;
        }

        try {
            ReportGenerator generator = ReportFactory.getGenerator(format);
            String reportContent = generator.generate(result);

            Path output = Paths.get(outputPath);
            Files.writeString(output, reportContent);

            ConsoleUI.success("Report exported to: " + outputPath);
            return true;

        } catch (IOException e) {
            ConsoleUI.error("Failed to export report: " + e.getMessage());
            return false;
        }
    }

    public boolean deleteReport(String reportId) {
        if (reportsDirectory == null) {
            return false;
        }

        try {
            Path metadataPath = reportsDirectory.resolve(reportId + "_metadata.json");
            Path resultPath = reportsDirectory.resolve(reportId + "_result.json");

            boolean deleted = false;
            if (Files.exists(metadataPath)) {
                Files.delete(metadataPath);
                deleted = true;
            }
            if (Files.exists(resultPath)) {
                Files.delete(resultPath);
                deleted = true;
            }

            if (deleted) {
                ConsoleUI.success("Report deleted: " + reportId);
            } else {
                ConsoleUI.warning("Report not found: " + reportId);
            }

            return deleted;

        } catch (IOException e) {
            ConsoleUI.error("Failed to delete report: " + e.getMessage());
            return false;
        }
    }

    @Setter
    @Getter
    public static class ReportMetadata {

        private String id;
        private String targetUrl;
        private LocalDateTime timestamp;
        private int totalVulnerabilities;
        private int criticalCount;
        private int highCount;
        private int mediumCount;
        private int lowCount;
        private long duration;

        public ReportMetadata(String id, String targetUrl, LocalDateTime timestamp,
                              int totalVulnerabilities, int criticalCount, int highCount,
                              int mediumCount, int lowCount, long duration) {
            this.id = id;
            this.targetUrl = targetUrl;
            this.timestamp = timestamp;
            this.totalVulnerabilities = totalVulnerabilities;
            this.criticalCount = criticalCount;
            this.highCount = highCount;
            this.mediumCount = mediumCount;
            this.lowCount = lowCount;
            this.duration = duration;
        }

    }
}
