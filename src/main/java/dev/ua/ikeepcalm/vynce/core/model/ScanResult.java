package dev.ua.ikeepcalm.vynce.core.model;

import dev.ua.ikeepcalm.vynce.core.model.source.Severity;
import lombok.Getter;
import lombok.Setter;

import java.util.List;

@Getter
public class ScanResult {

    @Setter
    private long duration;

    @Setter
    private int testCount;

    private final List<Vulnerability> vulnerabilities;

    public ScanResult() {
        this.vulnerabilities = new java.util.ArrayList<>();
    }

    public void addVulnerabilities(List<Vulnerability> vulnerabilities) {
        this.vulnerabilities.addAll(vulnerabilities);
    }

    public int getCriticalCount() {
        int criticalCount = 0;
        for (Vulnerability vulnerability : vulnerabilities) {
            if (vulnerability.getSeverity() == Severity.CRITICAL) {
                criticalCount++;
            }
        }

        return criticalCount;
    }

    public int getHighCount() {
        int highCount = 0;
        for (Vulnerability vulnerability : vulnerabilities) {
            if (vulnerability.getSeverity() == Severity.HIGH) {
                highCount++;
            }
        }

        return highCount;
    }

    public int getMediumCount() {
        int mediumCount = 0;
        for (Vulnerability vulnerability : vulnerabilities) {
            if (vulnerability.getSeverity() == Severity.MEDIUM) {
                mediumCount++;
            }
        }

        return mediumCount;
    }

    public int getLowCount() {
        int lowCount = 0;
        for (Vulnerability vulnerability : vulnerabilities) {
            if (vulnerability.getSeverity() == Severity.LOW) {
                lowCount++;
            }
        }

        return lowCount;
    }

}
