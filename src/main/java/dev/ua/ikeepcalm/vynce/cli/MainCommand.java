package dev.ua.ikeepcalm.vynce.cli;

import dev.ua.ikeepcalm.vynce.cli.report.ReportCommand;
import dev.ua.ikeepcalm.vynce.ui.ConsoleUI;
import picocli.CommandLine;
import picocli.CommandLine.Command;

@Command(
        name = "vulnscan",
        mixinStandardHelpOptions = true,
        version = "Vynce Web Vulnerability Scanner v1.0.0",
        description = "Advanced web vulnerability detection tool",
        footer = """
                @|yellow Examples:|@
                  vulnscan scan https://example.com
                  vulnscan scan https://example.com -t SQL,XSS --threads 10
                  vulnscan report list
                """,
        subcommands = {
                ScanCommand.class,
                ReportCommand.class,
//                ConfigCommand.class,
//                UpdateCommand.class,
                CommandLine.HelpCommand.class
        }
)
public class MainCommand implements Runnable {

    @CommandLine.Option(names = {"-v", "--verbose"},
            description = "Enable verbose output",
            scope = CommandLine.ScopeType.INHERIT)
    boolean verbose;

    @Override
    public void run() {
        ConsoleUI.showBanner();
    }
}