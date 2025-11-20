package dev.ua.ikeepcalm.vynce.report.impl;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import dev.ua.ikeepcalm.vynce.core.model.ScanResult;
import dev.ua.ikeepcalm.vynce.core.model.Vulnerability;
import dev.ua.ikeepcalm.vynce.core.model.source.Severity;
import dev.ua.ikeepcalm.vynce.report.ReportGenerator;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public class JsonReportGenerator implements ReportGenerator {

    private final ObjectMapper mapper;

    public JsonReportGenerator() {
        this.mapper = new ObjectMapper();
        this.mapper.enable(SerializationFeature.INDENT_OUTPUT);
    }

    @Override
    public String generate(ScanResult result) {
        try {
            Map<String, Object> report = new HashMap<>();

            Map<String, Object> metadata = new HashMap<>();
            metadata.put("timestamp", LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME));
            metadata.put("scanner", "Vynce Scanner");
            metadata.put("version", "1.0.0");
            metadata.put("duration_ms", result.getDuration());
            metadata.put("tests_executed", result.getTestCount());
            report.put("metadata", metadata);

            Map<String, Object> summary = new HashMap<>();
            summary.put("total_vulnerabilities", result.getVulnerabilities().size());
            summary.put("critical", countBySeverity(result.getVulnerabilities(), Severity.CRITICAL));
            summary.put("high", countBySeverity(result.getVulnerabilities(), Severity.HIGH));
            summary.put("medium", countBySeverity(result.getVulnerabilities(), Severity.MEDIUM));
            summary.put("low", countBySeverity(result.getVulnerabilities(), Severity.LOW));
            summary.put("info", countBySeverity(result.getVulnerabilities(), Severity.INFO));
            report.put("summary", summary);

            List<Map<String, String>> vulns = result.getVulnerabilities().stream()
                    .map(this::vulnerabilityToMap)
                    .collect(Collectors.toList());
            report.put("vulnerabilities", vulns);

            return mapper.writeValueAsString(report);
        } catch (Exception e) {
            return "{\"error\": \"Failed to generate JSON report: " + e.getMessage() + "\"}";
        }
    }

    private long countBySeverity(List<Vulnerability> vulnerabilities, Severity severity) {
        return vulnerabilities.stream()
                .filter(v -> v.severity() == severity)
                .count();
    }

    private Map<String, String> vulnerabilityToMap(Vulnerability vuln) {
        Map<String, String> map = new HashMap<>();
        map.put("type", vuln.type() != null ? vuln.type().name() : "UNKNOWN");
        map.put("severity", vuln.severity().name());
        map.put("title", vuln.title());
        map.put("description", vuln.description());
        map.put("url", vuln.url());
        map.put("payload", vuln.payload() != null ? vuln.payload() : "N/A");
        return map;
    }

    @Override
    public String getFileExtension() {
        return "json";
    }
}
