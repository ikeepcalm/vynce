package dev.ua.ikeepcalm.vynce.report;

import dev.ua.ikeepcalm.vynce.core.model.ScanResult;

public interface ReportGenerator {
    String generate(ScanResult result);

    String getFileExtension();
}
