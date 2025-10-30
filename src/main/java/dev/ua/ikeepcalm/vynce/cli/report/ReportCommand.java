package dev.ua.ikeepcalm.vynce.cli.report;

import dev.ua.ikeepcalm.vynce.ui.ConsoleUI;
import picocli.CommandLine.Command;

import java.util.concurrent.Callable;

@Command(
        name = "report",
        description = "Manage scan reports",
        subcommands = {
                ReportListCommand.class,
                ReportViewCommand.class,
                ReportExportCommand.class
        }
)
public class ReportCommand implements Callable<Integer> {
    @Override
    public Integer call() {
        ConsoleUI.info("Use 'vynce report --help' for available commands");
        return 0;
    }
}




