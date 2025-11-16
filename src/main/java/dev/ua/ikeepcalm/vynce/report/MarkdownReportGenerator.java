package dev.ua.ikeepcalm.vynce.report;

import dev.ua.ikeepcalm.vynce.core.model.ScanResult;
import dev.ua.ikeepcalm.vynce.core.model.Vulnerability;
import dev.ua.ikeepcalm.vynce.core.model.source.Severity;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;

public class MarkdownReportGenerator implements ReportGenerator {

    @Override
    public String generate(ScanResult result) {
        StringBuilder md = new StringBuilder();

        // Header
        md.append("# Vynce Security Scan Report\n\n");
        md.append("**Generated:** ").append(LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"))).append("\n\n");
        md.append("---\n\n");

        // Summary
        md.append("## Summary\n\n");
        md.append("| Metric | Count |\n");
        md.append("|--------|-------|\n");
        md.append("| Total Vulnerabilities | ").append(result.getVulnerabilities().size()).append(" |\n");
        md.append("| Critical | ").append(countBySeverity(result.getVulnerabilities(), Severity.CRITICAL)).append(" |\n");
        md.append("| High | ").append(countBySeverity(result.getVulnerabilities(), Severity.HIGH)).append(" |\n");
        md.append("| Medium | ").append(countBySeverity(result.getVulnerabilities(), Severity.MEDIUM)).append(" |\n");
        md.append("| Low | ").append(countBySeverity(result.getVulnerabilities(), Severity.LOW)).append(" |\n");
        md.append("| Info | ").append(countBySeverity(result.getVulnerabilities(), Severity.INFO)).append(" |\n");
        md.append("| Scan Duration | ").append(result.getDuration()).append("ms |\n");
        md.append("| Tests Executed | ").append(result.getTestCount()).append(" |\n\n");

        // Vulnerabilities
        if (!result.getVulnerabilities().isEmpty()) {
            md.append("## Vulnerabilities\n\n");

            // Group by severity
            for (Severity severity : Severity.values()) {
                List<Vulnerability> vulnsOfSeverity = result.getVulnerabilities().stream()
                        .filter(v -> v.getSeverity() == severity)
                        .toList();

                if (!vulnsOfSeverity.isEmpty()) {
                    md.append("### ").append(getSeverityEmoji(severity)).append(" ").append(severity.name()).append("\n\n");

                    for (Vulnerability vuln : vulnsOfSeverity) {
                        md.append("#### ").append(vuln.getTitle()).append("\n\n");
                        md.append("**Description:** ").append(vuln.getDescription()).append("\n\n");
                        md.append("**URL:** `").append(vuln.getUrl()).append("`\n\n");

                        if (vuln.getPayload() != null) {
                            md.append("**Payload:**\n```\n").append(vuln.getPayload()).append("\n```\n\n");
                        }

                        md.append("---\n\n");
                    }
                }
            }
        } else {
            md.append("## No Vulnerabilities Found\n\n");
            md.append("The scan did not detect any security vulnerabilities. ✅\n\n");
        }

        return md.toString();
    }

    private long countBySeverity(List<Vulnerability> vulnerabilities, Severity severity) {
        return vulnerabilities.stream()
                .filter(v -> v.getSeverity() == severity)
                .count();
    }

    private String getSeverityEmoji(Severity severity) {
        return switch (severity) {
            case CRITICAL -> "🔴";
            case HIGH -> "🟠";
            case MEDIUM -> "🟡";
            case LOW -> "🔵";
            case INFO -> "🟢";
        };
    }

    @Override
    public String getFileExtension() {
        return "md";
    }
}
