package dev.ua.ikeepcalm.vynce.ui;

import dev.ua.ikeepcalm.vynce.core.model.source.Severity;
import dev.ua.ikeepcalm.vynce.core.model.source.TestType;
import lombok.Getter;
import lombok.Setter;

import static org.fusesource.jansi.Ansi.Color;
import static org.fusesource.jansi.Ansi.Color.*;
import static org.fusesource.jansi.Ansi.ansi;

public class ConsoleUI {

    @Getter
    @Setter
    private static boolean verbose = false;

    public static void showBanner() {
        System.out.println(ansi().eraseScreen().cursor(1, 1));
        System.out.println(ansi().fg(CYAN).bold().a("""
                ██╗   ██╗██╗   ██╗███╗   ██╗ ██████╗███████╗
                ██║   ██║╚██╗ ██╔╝████╗  ██║██╔════╝██╔════╝
                ██║   ██║ ╚████╔╝ ██╔██╗ ██║██║     █████╗  
                ╚██╗ ██╔╝  ╚██╔╝  ██║╚██╗██║██║     ██╔══╝  
                 ╚████╔╝    ██║   ██║ ╚████║╚██████╗███████╗
                  ╚═══╝     ╚═╝   ╚═╝  ╚═══╝ ╚═════╝╚══════╝
                """).reset());

        System.out.println(ansi().fg(YELLOW).a("  Web Vulnerability Scanner v1.0.0").reset());
        System.out.println(ansi().fg(WHITE).a("  Type 'vynce --help' for usage\n").reset());
    }

    public static void info(String message) {
        System.out.println(ansi().fg(BLUE).a("[*] ").reset().a(message));
    }

    public static void success(String message) {
        System.out.println(ansi().fg(GREEN).a("[+] ").reset().a(message));
    }

    public static void warning(String message) {
        System.out.println(ansi().fg(YELLOW).a("[!] ").reset().a(message));
    }

    public static void error(String message) {
        System.out.println(ansi().fg(RED).a("[-] ").reset().a(message));
    }

    public static void critical(String message) {
        System.out.println(ansi().fg(RED).bold().a("[CRITICAL] ").reset()
                .fg(RED).a(message).reset());
    }

    public static void vulnerability(TestType type, Severity severity, String message) {
        Color color = switch (severity) {
            case CRITICAL -> RED;
            case HIGH -> MAGENTA;
            case MEDIUM -> YELLOW;
            case LOW -> CYAN;
            default -> GREEN;
        };

        System.out.println(ansi()
                .fg(color).a("[" + severity + "] ")
                .fg(WHITE).a(type + ": ")
                .reset().a(message));
    }

    public static void printSection(String title) {
        System.out.println("\n" + ansi().fg(CYAN).bold()
                .a("═══════════════════════════════════════════════════════")
                .reset());
        System.out.println(ansi().fg(CYAN).bold().a("  " + title).reset());
        System.out.println(ansi().fg(CYAN).bold()
                                   .a("═══════════════════════════════════════════════════════")
                                   .reset() + "\n");
    }

    public static void printSubSection(String title) {
        System.out.println("\n" + ansi().fg(YELLOW).a("▶ " + title).reset());
        System.out.println(ansi().fg(YELLOW).a("  " + "─".repeat(title.length())).reset());
    }

    public static void debug(String message) {
        if (verbose) {
            System.out.println(ansi().fg(WHITE).a("[DEBUG] ").reset().a(message));
        }
    }

    public static void debug(String format, Object... args) {
        if (verbose) {
            System.out.println(ansi().fg(WHITE).a("[DEBUG] ").reset().a(String.format(format, args)));
        }
    }

}