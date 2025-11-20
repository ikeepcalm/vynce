package dev.ua.ikeepcalm.vynce.tests.impl;

import dev.ua.ikeepcalm.vynce.core.model.ScanContext;
import dev.ua.ikeepcalm.vynce.core.model.source.Severity;
import dev.ua.ikeepcalm.vynce.core.model.source.TestType;
import dev.ua.ikeepcalm.vynce.tests.BaseVulnerabilityTest;
import okhttp3.Response;

import java.util.HashMap;
import java.util.Map;

public class SecurityHeadersTest extends BaseVulnerabilityTest {

    private static final Map<String, SecurityHeader> REQUIRED_HEADERS = new HashMap<>();

    static {
        REQUIRED_HEADERS.put("X-Frame-Options", new SecurityHeader(
                Severity.MEDIUM,
                "Missing X-Frame-Options header. Recommended: DENY or SAMEORIGIN",
                "Protects against clickjacking attacks"
        ));

        REQUIRED_HEADERS.put("X-Content-Type-Options", new SecurityHeader(
                Severity.MEDIUM,
                "Missing X-Content-Type-Options header. Recommended: nosniff",
                "Prevents MIME type sniffing"
        ));

        REQUIRED_HEADERS.put("X-XSS-Protection", new SecurityHeader(
                Severity.LOW,
                "Missing X-XSS-Protection header. Recommended: 1; mode=block",
                "Legacy XSS protection (deprecated but still useful)"
        ));

        REQUIRED_HEADERS.put("Strict-Transport-Security", new SecurityHeader(
                Severity.HIGH,
                "Missing Strict-Transport-Security header. Recommended: max-age=31536000; includeSubDomains",
                "Enforces HTTPS connections"
        ));

        REQUIRED_HEADERS.put("Content-Security-Policy", new SecurityHeader(
                Severity.MEDIUM,
                "Missing Content-Security-Policy header",
                "Prevents XSS and data injection attacks"
        ));

        REQUIRED_HEADERS.put("Referrer-Policy", new SecurityHeader(
                Severity.LOW,
                "Missing Referrer-Policy header. Recommended: no-referrer or strict-origin-when-cross-origin",
                "Controls referrer information"
        ));

        REQUIRED_HEADERS.put("Permissions-Policy", new SecurityHeader(
                Severity.LOW,
                "Missing Permissions-Policy header",
                "Controls browser features and APIs"
        ));
    }

    @Override
    public TestType getTestType() {
        return TestType.HEADERS;
    }

    @Override
    protected int estimateTestSteps(ScanContext context) {
        int count = REQUIRED_HEADERS.size() + 2;
        if (context.getTargetUrl().startsWith("https://")) {
            count++;
        }
        return count;
    }

    @Override
    protected void runTests(ScanContext context) throws Exception {
        try (Response response = context.getHttpClient().get(context.getTargetUrl())) {

            for (Map.Entry<String, SecurityHeader> entry : REQUIRED_HEADERS.entrySet()) {
                String headerName = entry.getKey();
                advanceProgress("Header: " + headerName);
                String headerValue = response.header(headerName);

                if (headerValue == null || headerValue.trim().isEmpty()) {
                    SecurityHeader header = entry.getValue();
                    addVulnerability(createVulnerability(
                            header.severity,
                            "Missing " + headerName + " Header",
                            header.description + " - " + header.purpose,
                            context.getTargetUrl(),
                            null
                    ));
                }
            }

            advanceProgress("Information disclosure");
            checkInformationDisclosure(response, context);

            if (context.getTargetUrl().startsWith("https://")) {
                advanceProgress("HSTS configuration");
                checkHsts(response, context);
            }
        }
    }

    private void checkInformationDisclosure(Response response, ScanContext context) {
        String serverHeader = response.header("Server");
        if (serverHeader != null && !serverHeader.isEmpty()) {
            addVulnerability(createVulnerability(
                    Severity.LOW,
                    "Information Disclosure - Server Header",
                    "Server header exposes version information: " + serverHeader,
                    context.getTargetUrl(),
                    "Server: " + serverHeader
            ));
        }

        String xPoweredBy = response.header("X-Powered-By");
        if (xPoweredBy != null && !xPoweredBy.isEmpty()) {
            addVulnerability(createVulnerability(
                    Severity.LOW,
                    "Information Disclosure - X-Powered-By Header",
                    "X-Powered-By header exposes technology information: " + xPoweredBy,
                    context.getTargetUrl(),
                    "X-Powered-By: " + xPoweredBy
            ));
        }
    }

    private void checkHsts(Response response, ScanContext context) {
        String hsts = response.header("Strict-Transport-Security");
        if (hsts != null) {
            if (!hsts.contains("includeSubDomains")) {
                addVulnerability(createVulnerability(
                        Severity.MEDIUM,
                        "Weak HSTS Configuration",
                        "HSTS header present but missing 'includeSubDomains' directive",
                        context.getTargetUrl(),
                        "Strict-Transport-Security: " + hsts
                ));
            }

            if (hsts.contains("max-age=")) {
                String[] parts = hsts.split("max-age=");
                if (parts.length > 1) {
                    try {
                        String maxAgeStr = parts[1].split("[;,]")[0].trim();
                        long maxAge = Long.parseLong(maxAgeStr);
                        if (maxAge < 15768000) { // 6 months in seconds
                            addVulnerability(createVulnerability(
                                    Severity.MEDIUM,
                                    "Weak HSTS Max-Age",
                                    "HSTS max-age is too short (" + maxAge + " seconds). Recommended: at least 15768000 (6 months)",
                                    context.getTargetUrl(),
                                    "Strict-Transport-Security: " + hsts
                            ));
                        }
                    } catch (NumberFormatException ignored) {
                    }
                }
            }
        }
    }

    private record SecurityHeader(Severity severity, String description, String purpose) {
    }
}
