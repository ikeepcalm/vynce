package dev.ua.ikeepcalm.vynce.cli.report;

import dev.ua.ikeepcalm.vynce.core.model.ScanResult;
import dev.ua.ikeepcalm.vynce.core.model.Vulnerability;
import dev.ua.ikeepcalm.vynce.core.model.source.Severity;
import dev.ua.ikeepcalm.vynce.report.ReportManager;
import dev.ua.ikeepcalm.vynce.report.ReportManager.ReportMetadata;
import dev.ua.ikeepcalm.vynce.ui.ConsoleUI;
import picocli.CommandLine;

import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.concurrent.Callable;

@CommandLine.Command(name = "view", description = "View a specific scan report")
class ReportViewCommand implements Callable<Integer> {

    @CommandLine.Parameters(index = "0", description = "Report ID")
    private String reportId;

    @CommandLine.Option(names = {"-d", "--detailed"}, description = "Show detailed vulnerability information")
    private boolean detailed = false;

    private static final DateTimeFormatter DISPLAY_FORMAT =
        DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    @Override
    public Integer call() {
        ReportManager manager = new ReportManager();

        // Load metadata
        ReportMetadata metadata = manager.getReportMetadata(reportId);
        if (metadata == null) {
            ConsoleUI.error("Report not found: " + reportId);
            ConsoleUI.info("Use 'vynce report list' to see available reports");
            return 1;
        }

        // Load full report
        ScanResult result = manager.loadReport(reportId);
        if (result == null) {
            ConsoleUI.error("Failed to load report data");
            return 1;
        }

        // Display report
        displayReport(metadata, result);

        return 0;
    }

    private void displayReport(ReportMetadata metadata, ScanResult result) {
        ConsoleUI.printSection("SCAN REPORT: " + metadata.getId());

        // Metadata section
        System.out.println();
        ConsoleUI.info("Target URL: " + metadata.getTargetUrl());
        ConsoleUI.info("Scan Date: " + metadata.getTimestamp().format(DISPLAY_FORMAT));
        ConsoleUI.info("Duration: " + formatDuration(metadata.getDuration()));
        System.out.println();

        // Summary section
        ConsoleUI.printSubSection("Vulnerability Summary");
        System.out.println("  Total Vulnerabilities: " + metadata.getTotalVulnerabilities());
        if (metadata.getCriticalCount() > 0) {
            System.out.println("  🔴 Critical: " + metadata.getCriticalCount());
        }
        if (metadata.getHighCount() > 0) {
            System.out.println("  🟠 High: " + metadata.getHighCount());
        }
        if (metadata.getMediumCount() > 0) {
            System.out.println("  🟡 Medium: " + metadata.getMediumCount());
        }
        if (metadata.getLowCount() > 0) {
            System.out.println("  🔵 Low: " + metadata.getLowCount());
        }
        System.out.println();

        // Vulnerabilities section
        if (result.getVulnerabilities().isEmpty()) {
            ConsoleUI.success("No vulnerabilities found!");
        } else {
            if (detailed) {
                displayDetailedVulnerabilities(result.getVulnerabilities());
            } else {
                displaySummaryVulnerabilities(result.getVulnerabilities());
                System.out.println();
                ConsoleUI.info("Use --detailed flag to see full vulnerability details");
            }
        }

        System.out.println();
        ConsoleUI.info("Export options:");
        ConsoleUI.info("  vynce report export " + metadata.getId() + " output.html html");
        ConsoleUI.info("  vynce report export " + metadata.getId() + " output.md markdown");
    }

    private void displaySummaryVulnerabilities(List<Vulnerability> vulnerabilities) {
        ConsoleUI.printSubSection("Vulnerabilities");

        for (Severity severity : Severity.values()) {
            List<Vulnerability> vulnsOfSeverity = vulnerabilities.stream()
                .filter(v -> v.getSeverity() == severity)
                .toList();

            if (!vulnsOfSeverity.isEmpty()) {
                System.out.println("\n" + getSeverityEmoji(severity) + " " + severity.name() + ":");
                for (Vulnerability vuln : vulnsOfSeverity) {
                    System.out.println("  • " + vuln.getTitle());
                    if (vuln.getType() != null) {
                        System.out.println("    Type: " + vuln.getType().name());
                    }
                }
            }
        }
    }

    private void displayDetailedVulnerabilities(List<Vulnerability> vulnerabilities) {
        ConsoleUI.printSubSection("Detailed Vulnerabilities");

        for (Severity severity : Severity.values()) {
            List<Vulnerability> vulnsOfSeverity = vulnerabilities.stream()
                .filter(v -> v.getSeverity() == severity)
                .toList();

            if (!vulnsOfSeverity.isEmpty()) {
                System.out.println("\n" + getSeverityEmoji(severity) + " " + severity.name() + ":");
                for (Vulnerability vuln : vulnsOfSeverity) {
                    System.out.println("  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
                    System.out.println("  Title: " + vuln.getTitle());
                    if (vuln.getType() != null) {
                        System.out.println("  Type: " + vuln.getType().name());
                    }
                    System.out.println("  Description: " + vuln.getDescription());
                    System.out.println("  URL: " + vuln.getUrl());
                    if (vuln.getPayload() != null) {
                        System.out.println("  Payload: " + vuln.getPayload());
                    }
                }
                System.out.println();
            }
        }
    }

    private String getSeverityEmoji(Severity severity) {
        return switch (severity) {
            case CRITICAL -> "🔴";
            case HIGH -> "🟠";
            case MEDIUM -> "🟡";
            case LOW -> "🔵";
            case INFO -> "ℹ️";
        };
    }

    private String formatDuration(long milliseconds) {
        long seconds = milliseconds / 1000;
        long minutes = seconds / 60;
        seconds = seconds % 60;

        if (minutes > 0) {
            return String.format("%d min %d sec", minutes, seconds);
        } else {
            return String.format("%d sec", seconds);
        }
    }
}
