package dev.ua.ikeepcalm.vynce.core.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import dev.ua.ikeepcalm.vynce.core.model.source.Severity;
import lombok.Getter;
import lombok.Setter;

import java.util.List;

@Getter
@JsonIgnoreProperties(ignoreUnknown = true)
public class ScanResult {

    private final List<Vulnerability> vulnerabilities;
    @Setter

    private long duration;
    @Setter

    private int testCount;

    public ScanResult() {
        this.vulnerabilities = new java.util.ArrayList<>();
    }

    public void addVulnerabilities(List<Vulnerability> vulnerabilities) {
        this.vulnerabilities.addAll(vulnerabilities);
    }

    @JsonIgnore
    public int getCriticalCount() {
        int criticalCount = 0;
        for (Vulnerability vulnerability : vulnerabilities) {
            if (vulnerability.severity() == Severity.CRITICAL) {
                criticalCount++;
            }
        }

        return criticalCount;
    }

    @JsonIgnore
    public int getHighCount() {
        int highCount = 0;
        for (Vulnerability vulnerability : vulnerabilities) {
            if (vulnerability.severity() == Severity.HIGH) {
                highCount++;
            }
        }

        return highCount;
    }

    @JsonIgnore
    public int getMediumCount() {
        int mediumCount = 0;
        for (Vulnerability vulnerability : vulnerabilities) {
            if (vulnerability.severity() == Severity.MEDIUM) {
                mediumCount++;
            }
        }

        return mediumCount;
    }

    @JsonIgnore
    public int getLowCount() {
        int lowCount = 0;
        for (Vulnerability vulnerability : vulnerabilities) {
            if (vulnerability.severity() == Severity.LOW) {
                lowCount++;
            }
        }

        return lowCount;
    }

}
