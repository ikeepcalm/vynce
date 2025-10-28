package dev.ua.ikeepcalm.vynce.cli.report;

import dev.ua.ikeepcalm.vynce.ui.ConsoleUI;
import picocli.CommandLine;

import java.util.concurrent.Callable;

@CommandLine.Command(name = "list", description = "List all scan reports")
class ReportListCommand implements Callable<Integer> {

    @Override
    public Integer call() {
        ConsoleUI.printSection("SCAN REPORTS");

        // Stub implementation
        System.out.println("ID    Date                Target                    Vulnerabilities");
        System.out.println("────  ──────────────────  ────────────────────────  ───────────────");
        System.out.println("001   2025-01-28 10:30   https://example.com       3 High, 5 Medium");
        System.out.println("002   2025-01-28 11:45   https://testsite.org      1 Critical, 2 High");
        System.out.println("003   2025-01-28 14:20   https://vulnerable.app    No issues found");

        return 0;
    }
}
