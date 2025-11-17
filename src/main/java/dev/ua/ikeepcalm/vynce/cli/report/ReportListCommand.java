package dev.ua.ikeepcalm.vynce.cli.report;

import dev.ua.ikeepcalm.vynce.report.ReportManager;
import dev.ua.ikeepcalm.vynce.report.ReportManager.ReportMetadata;
import dev.ua.ikeepcalm.vynce.ui.ConsoleUI;
import picocli.CommandLine;

import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.concurrent.Callable;

@CommandLine.Command(name = "list", description = "List all saved scan reports")
class ReportListCommand implements Callable<Integer> {

    private static final DateTimeFormatter DISPLAY_FORMAT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    @Override
    public Integer call() {
        ConsoleUI.printSection("SAVED SCAN REPORTS");

        ReportManager manager = new ReportManager();
        List<ReportMetadata> reports = manager.listReports();

        if (reports.isEmpty()) {
            ConsoleUI.info("No saved reports found.");
            ConsoleUI.info("Reports are saved in: " + manager.getReportsDirectory());
            return 0;
        }

        System.out.printf("%-20s %-25s %-40s %-30s%n", "ID", "Date", "Target", "Vulnerabilities");
        System.out.println("─".repeat(120));

        for (ReportMetadata report : reports) {
            String timestamp = report.getTimestamp().format(DISPLAY_FORMAT);
            String target = truncate(report.getTargetUrl(), 38);
            String vulnerabilities = formatVulnerabilities(report);

            System.out.printf("%-20s %-25s %-40s %-30s%n", report.getId(), timestamp, target, vulnerabilities);
        }

        System.out.println();
        ConsoleUI.info("Total reports: " + reports.size());
        ConsoleUI.info("Use 'vynce report view <ID>' to see details");

        return 0;
    }

    private String formatVulnerabilities(ReportMetadata report) {
        if (report.getTotalVulnerabilities() == 0) {
            return "No issues found";
        }

        StringBuilder sb = new StringBuilder();
        if (report.getCriticalCount() > 0) {
            sb.append(report.getCriticalCount()).append(" Critical, ");
        }
        if (report.getHighCount() > 0) {
            sb.append(report.getHighCount()).append(" High, ");
        }
        if (report.getMediumCount() > 0) {
            sb.append(report.getMediumCount()).append(" Medium, ");
        }
        if (report.getLowCount() > 0) {
            sb.append(report.getLowCount()).append(" Low, ");
        }

        if (sb.length() > 2) {
            sb.setLength(sb.length() - 2);
        }

        return sb.toString();
    }

    private String truncate(String str, int maxLength) {
        if (str == null) return "";
        if (str.length() <= maxLength) return str;
        return str.substring(0, maxLength - 3) + "...";
    }
}
