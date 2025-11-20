package dev.ua.ikeepcalm.vynce;


import dev.ua.ikeepcalm.vynce.cli.MainCommand;
import dev.ua.ikeepcalm.vynce.ui.ConsoleUI;
import org.fusesource.jansi.AnsiConsole;
import picocli.CommandLine;

import java.util.logging.Level;
import java.util.logging.Logger;

public class VynceApplication {

    public static void main(String[] args) {
        Logger.getLogger("okhttp3.OkHttpClient").setLevel(Level.SEVERE);
        Logger.getLogger("okhttp3.internal.platform.Platform").setLevel(Level.SEVERE);

        AnsiConsole.systemInstall();

        for (String arg : args) {
            if (arg.equals("-h") || arg.equals("--help")) {
                ConsoleUI.showBanner();
                break;
            }
        }

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