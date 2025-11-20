package dev.ua.ikeepcalm.vynce.report;

import dev.ua.ikeepcalm.vynce.report.impl.HtmlReportGenerator;
import dev.ua.ikeepcalm.vynce.report.impl.JsonReportGenerator;
import dev.ua.ikeepcalm.vynce.report.impl.MarkdownReportGenerator;

import java.util.HashMap;
import java.util.Map;

public class ReportFactory {

    private static final Map<ReportFormat, ReportGenerator> generators = new HashMap<>();

    static {
        generators.put(ReportFormat.JSON, new JsonReportGenerator());
        generators.put(ReportFormat.HTML, new HtmlReportGenerator());
        generators.put(ReportFormat.MARKDOWN, new MarkdownReportGenerator());
    }

    public static ReportGenerator getGenerator(ReportFormat format) {
        ReportGenerator generator = generators.get(format);
        if (generator == null) {
            throw new IllegalArgumentException("Unsupported report format: " + format);
        }
        return generator;
    }


    public static ReportGenerator getGenerator(String formatName) {
        ReportFormat format = switch (formatName.toLowerCase()) {
            case "json" -> ReportFormat.JSON;
            case "html" -> ReportFormat.HTML;
            case "markdown", "md" -> ReportFormat.MARKDOWN;
            default -> throw new IllegalArgumentException("Unsupported report format: " + formatName);
        };
        return getGenerator(format);
    }

    public enum ReportFormat {
        JSON, HTML, MARKDOWN
    }
}
