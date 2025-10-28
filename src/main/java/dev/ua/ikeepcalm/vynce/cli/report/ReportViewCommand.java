package dev.ua.ikeepcalm.vynce.cli.report;

import dev.ua.ikeepcalm.vynce.ui.ConsoleUI;
import picocli.CommandLine;

import java.util.concurrent.Callable;

@CommandLine.Command(name = "view", description = "View a specific report")
class ReportViewCommand implements Callable<Integer> {

    @CommandLine.Parameters(index = "0", description = "Report ID")
    private String reportId;

    @Override
    public Integer call() {
        ConsoleUI.printSection("REPORT #" + reportId);
        ConsoleUI.info("Loading report...");

        // Stub implementation
        ConsoleUI.success("Report loaded successfully");

        return 0;
    }
}