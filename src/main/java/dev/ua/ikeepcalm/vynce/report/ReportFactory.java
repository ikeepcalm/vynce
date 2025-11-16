package dev.ua.ikeepcalm.vynce.report;

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

    public enum ReportFormat {
        JSON, HTML, MARKDOWN
    }
}
