package dev.ua.ikeepcalm.vynce.cli.report;

import dev.ua.ikeepcalm.vynce.report.ReportManager;
import dev.ua.ikeepcalm.vynce.ui.ConsoleUI;
import picocli.CommandLine;

import java.util.concurrent.Callable;

@CommandLine.Command(name = "export", description = "Export report to different formats")
class ReportExportCommand implements Callable<Integer> {

    @CommandLine.Parameters(index = "0", description = "Report ID")
    private String reportId;

    @CommandLine.Parameters(index = "1", description = "Output file path")
    private String outputFile;

    @CommandLine.Parameters(index = "2", description = "Format: json, html, or markdown",
                          defaultValue = "html")
    private String format;

    @Override
    public Integer call() {
        // Validate format
        String normalizedFormat = format.toLowerCase();
        if (!normalizedFormat.equals("json") &&
            !normalizedFormat.equals("html") &&
            !normalizedFormat.equals("markdown") &&
            !normalizedFormat.equals("md")) {
            ConsoleUI.error("Invalid format: " + format);
            ConsoleUI.info("Supported formats: json, html, markdown (or md)");
            return 1;
        }

        // Normalize 'md' to 'markdown'
        if (normalizedFormat.equals("md")) {
            normalizedFormat = "markdown";
        }

        ConsoleUI.info("Exporting report " + reportId + " to " + outputFile + " (format: " + normalizedFormat + ")");

        ReportManager manager = new ReportManager();
        boolean success = manager.exportReport(reportId, outputFile, normalizedFormat);

        if (!success) {
            ConsoleUI.error("Failed to export report");
            ConsoleUI.info("Use 'vynce report list' to see available reports");
            return 1;
        }

        return 0;
    }
}
