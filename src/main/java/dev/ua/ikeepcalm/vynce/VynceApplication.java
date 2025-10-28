package dev.ua.ikeepcalm.vynce;


import dev.ua.ikeepcalm.vynce.cli.MainCommand;
import dev.ua.ikeepcalm.vynce.ui.ConsoleUI;
import org.fusesource.jansi.AnsiConsole;
import picocli.CommandLine;

public class VynceApplication {

    public static void main(String[] args) {
        AnsiConsole.systemInstall();

//        if (args.length == 0) {
//            ConsoleUI.showBanner();
//        }

        MainCommand mainCommand = new MainCommand();
        CommandLine commandLine = new CommandLine(mainCommand);
        commandLine.setExecutionExceptionHandler(new ExceptionHandler());

        int exitCode = commandLine.execute(args);
        AnsiConsole.systemUninstall();
        System.exit(exitCode);
    }

    static class ExceptionHandler implements CommandLine.IExecutionExceptionHandler {
        @Override
        public int handleExecutionException(Exception ex, CommandLine commandLine,
                                            CommandLine.ParseResult parseResult) {
            ConsoleUI.error("Execution failed: " + ex.getMessage());
            if (commandLine.getCommandSpec().commandLine().isUsageHelpRequested()) {
                commandLine.usage(commandLine.getErr());
            }
            return 1;
        }
    }

}