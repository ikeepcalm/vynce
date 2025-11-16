package dev.ua.ikeepcalm.vynce.report;

import dev.ua.ikeepcalm.vynce.core.model.ScanResult;
import dev.ua.ikeepcalm.vynce.core.model.Vulnerability;
import dev.ua.ikeepcalm.vynce.core.model.source.Severity;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;

public class HtmlReportGenerator implements ReportGenerator {

    @Override
    public String generate(ScanResult result) {
        StringBuilder html = new StringBuilder();

        html.append("<!DOCTYPE html>\n");
        html.append("<html lang=\"en\">\n");
        html.append("<head>\n");
        html.append("    <meta charset=\"UTF-8\">\n");
        html.append("    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n");
        html.append("    <title>Vynce Security Scan Report</title>\n");
        html.append("    <style>\n");
        html.append(getStyles());
        html.append("    </style>\n");
        html.append("</head>\n");
        html.append("<body>\n");

        // Header
        html.append("    <div class=\"header\">\n");
        html.append("        <h1>Vynce Security Scan Report</h1>\n");
        html.append("        <p class=\"timestamp\">Generated: ")
                .append(LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")))
                .append("</p>\n");
        html.append("    </div>\n");

        // Summary
        html.append("    <div class=\"summary\">\n");
        html.append("        <h2>Summary</h2>\n");
        html.append("        <div class=\"summary-grid\">\n");
        html.append("            <div class=\"summary-item\">\n");
        html.append("                <div class=\"summary-label\">Total Vulnerabilities</div>\n");
        html.append("                <div class=\"summary-value\">").append(result.getVulnerabilities().size()).append("</div>\n");
        html.append("            </div>\n");
        html.append("            <div class=\"summary-item critical\">\n");
        html.append("                <div class=\"summary-label\">Critical</div>\n");
        html.append("                <div class=\"summary-value\">").append(countBySeverity(result.getVulnerabilities(), Severity.CRITICAL)).append("</div>\n");
        html.append("            </div>\n");
        html.append("            <div class=\"summary-item high\">\n");
        html.append("                <div class=\"summary-label\">High</div>\n");
        html.append("                <div class=\"summary-value\">").append(countBySeverity(result.getVulnerabilities(), Severity.HIGH)).append("</div>\n");
        html.append("            </div>\n");
        html.append("            <div class=\"summary-item medium\">\n");
        html.append("                <div class=\"summary-label\">Medium</div>\n");
        html.append("                <div class=\"summary-value\">").append(countBySeverity(result.getVulnerabilities(), Severity.MEDIUM)).append("</div>\n");
        html.append("            </div>\n");
        html.append("            <div class=\"summary-item low\">\n");
        html.append("                <div class=\"summary-label\">Low</div>\n");
        html.append("                <div class=\"summary-value\">").append(countBySeverity(result.getVulnerabilities(), Severity.LOW)).append("</div>\n");
        html.append("            </div>\n");
        html.append("            <div class=\"summary-item info\">\n");
        html.append("                <div class=\"summary-label\">Info</div>\n");
        html.append("                <div class=\"summary-value\">").append(countBySeverity(result.getVulnerabilities(), Severity.INFO)).append("</div>\n");
        html.append("            </div>\n");
        html.append("        </div>\n");
        html.append("        <p class=\"scan-info\">Scan Duration: ").append(result.getDuration()).append("ms | Tests Executed: ").append(result.getTestCount()).append("</p>\n");
        html.append("    </div>\n");

        // Vulnerabilities
        if (!result.getVulnerabilities().isEmpty()) {
            html.append("    <div class=\"vulnerabilities\">\n");
            html.append("        <h2>Vulnerabilities</h2>\n");

            for (Vulnerability vuln : result.getVulnerabilities()) {
                html.append("        <div class=\"vulnerability ").append(vuln.getSeverity().name().toLowerCase()).append("\">\n");
                html.append("            <div class=\"vuln-header\">\n");
                html.append("                <span class=\"severity-badge ").append(vuln.getSeverity().name().toLowerCase()).append("\">")
                        .append(vuln.getSeverity().name()).append("</span>\n");
                html.append("                <h3>").append(escapeHtml(vuln.getTitle())).append("</h3>\n");
                html.append("            </div>\n");
                html.append("            <p class=\"vuln-description\">").append(escapeHtml(vuln.getDescription())).append("</p>\n");
                html.append("            <div class=\"vuln-details\">\n");
                html.append("                <p><strong>URL:</strong> <code>").append(escapeHtml(vuln.getUrl())).append("</code></p>\n");
                if (vuln.getPayload() != null) {
                    html.append("                <p><strong>Payload:</strong> <code>").append(escapeHtml(vuln.getPayload())).append("</code></p>\n");
                }
                html.append("            </div>\n");
                html.append("        </div>\n");
            }

            html.append("    </div>\n");
        } else {
            html.append("    <div class=\"no-vulns\">\n");
            html.append("        <h2>No Vulnerabilities Found</h2>\n");
            html.append("        <p>The scan did not detect any security vulnerabilities.</p>\n");
            html.append("    </div>\n");
        }

        html.append("</body>\n");
        html.append("</html>");

        return html.toString();
    }

    private long countBySeverity(List<Vulnerability> vulnerabilities, Severity severity) {
        return vulnerabilities.stream()
                .filter(v -> v.getSeverity() == severity)
                .count();
    }

    private String escapeHtml(String text) {
        if (text == null) return "";
        return text.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("'", "&#39;");
    }

    private String getStyles() {
        return """
                body {
                    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
                    line-height: 1.6;
                    color: #333;
                    max-width: 1200px;
                    margin: 0 auto;
                    padding: 20px;
                    background-color: #f5f5f5;
                }
                .header {
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                    padding: 30px;
                    border-radius: 10px;
                    margin-bottom: 30px;
                    box-shadow: 0 4px 6px rgba(0,0,0,0.1);
                }
                .header h1 {
                    margin: 0;
                    font-size: 2.5em;
                }
                .timestamp {
                    margin: 10px 0 0 0;
                    opacity: 0.9;
                }
                .summary {
                    background: white;
                    padding: 25px;
                    border-radius: 10px;
                    margin-bottom: 30px;
                    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                }
                .summary h2 {
                    margin-top: 0;
                    color: #667eea;
                }
                .summary-grid {
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
                    gap: 15px;
                    margin-bottom: 20px;
                }
                .summary-item {
                    background: #f8f9fa;
                    padding: 20px;
                    border-radius: 8px;
                    text-align: center;
                }
                .summary-label {
                    font-size: 0.9em;
                    color: #666;
                    margin-bottom: 5px;
                }
                .summary-value {
                    font-size: 2em;
                    font-weight: bold;
                    color: #333;
                }
                .summary-item.critical { background-color: #fee; }
                .summary-item.critical .summary-value { color: #d32f2f; }
                .summary-item.high { background-color: #fff3e0; }
                .summary-item.high .summary-value { color: #f57c00; }
                .summary-item.medium { background-color: #fff8e1; }
                .summary-item.medium .summary-value { color: #fbc02d; }
                .summary-item.low { background-color: #e3f2fd; }
                .summary-item.low .summary-value { color: #1976d2; }
                .summary-item.info { background-color: #e8f5e9; }
                .summary-item.info .summary-value { color: #388e3c; }
                .scan-info {
                    text-align: center;
                    color: #666;
                    margin-top: 20px;
                }
                .vulnerabilities h2 {
                    color: #667eea;
                    margin-bottom: 20px;
                }
                .vulnerability {
                    background: white;
                    padding: 20px;
                    margin-bottom: 20px;
                    border-radius: 8px;
                    border-left: 4px solid #ddd;
                    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                }
                .vulnerability.critical { border-left-color: #d32f2f; }
                .vulnerability.high { border-left-color: #f57c00; }
                .vulnerability.medium { border-left-color: #fbc02d; }
                .vulnerability.low { border-left-color: #1976d2; }
                .vulnerability.info { border-left-color: #388e3c; }
                .vuln-header {
                    display: flex;
                    align-items: center;
                    gap: 15px;
                    margin-bottom: 15px;
                }
                .vuln-header h3 {
                    margin: 0;
                    flex: 1;
                }
                .severity-badge {
                    padding: 5px 12px;
                    border-radius: 20px;
                    font-size: 0.8em;
                    font-weight: bold;
                    text-transform: uppercase;
                    color: white;
                }
                .severity-badge.critical { background-color: #d32f2f; }
                .severity-badge.high { background-color: #f57c00; }
                .severity-badge.medium { background-color: #fbc02d; }
                .severity-badge.low { background-color: #1976d2; }
                .severity-badge.info { background-color: #388e3c; }
                .vuln-description {
                    color: #666;
                    margin-bottom: 15px;
                }
                .vuln-details {
                    background: #f8f9fa;
                    padding: 15px;
                    border-radius: 5px;
                }
                .vuln-details p {
                    margin: 8px 0;
                }
                code {
                    background: #e0e0e0;
                    padding: 2px 6px;
                    border-radius: 3px;
                    font-family: 'Courier New', monospace;
                    font-size: 0.9em;
                    word-break: break-all;
                }
                .no-vulns {
                    background: white;
                    padding: 40px;
                    border-radius: 10px;
                    text-align: center;
                    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                }
                .no-vulns h2 {
                    color: #388e3c;
                }
                """;
    }

    @Override
    public String getFileExtension() {
        return "html";
    }
}
