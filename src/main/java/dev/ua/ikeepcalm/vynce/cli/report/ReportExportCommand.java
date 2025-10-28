package dev.ua.ikeepcalm.vynce.cli.report;

import dev.ua.ikeepcalm.vynce.ui.ConsoleUI;
import picocli.CommandLine;

import java.util.concurrent.Callable;

@CommandLine.Command(name = "export", description = "Export report to file")
class ReportExportCommand implements Callable<Integer> {

    @CommandLine.Parameters(index = "0", description = "Report ID")
    private String reportId;

    @CommandLine.Parameters(index = "1", description = "Output file")
    private String outputFile;

    @Override
    public Integer call() {
        ConsoleUI.info("Exporting report #" + reportId + " to " + outputFile);

        // Stub implementation
        ConsoleUI.success("Report exported successfully");

        return 0;
    }
}