package dev.ua.ikeepcalm.vynce.tests.impl;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.ua.ikeepcalm.vynce.core.model.ScanContext;
import dev.ua.ikeepcalm.vynce.core.model.source.Severity;
import dev.ua.ikeepcalm.vynce.core.model.source.TestType;
import dev.ua.ikeepcalm.vynce.tests.BaseVulnerabilityTest;
import okhttp3.Response;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.InputStream;
import java.util.HashMap;
import java.util.Map;

public class SecurityHeadersTest extends BaseVulnerabilityTest {

    private static final Logger logger = LoggerFactory.getLogger(SecurityHeadersTest.class);
    private Map<String, SecurityHeader> requiredHeaders;

    @Override
    public TestType getTestType() {
        return TestType.HEADERS;
    }

    @Override
    protected int estimateTestSteps(ScanContext context) {
        loadPayloads();
        int count = requiredHeaders.size() + 2;
        if (context.getTargetUrl().startsWith("https://")) {
            count++;
        }
        return count;
    }

    private void loadPayloads() {
        requiredHeaders = new HashMap<>();
        ObjectMapper mapper = new ObjectMapper();

        try (InputStream is = getClass().getClassLoader()
                .getResourceAsStream("payloads/security-headers.json")) {

            if (is == null) {
                logger.error("Payload file not found: payloads/security-headers.json");
                return;
            }

            JsonNode root = mapper.readTree(is);
            JsonNode headersNode = root.get("required_headers");

            if (headersNode != null && headersNode.isObject()) {
                headersNode.fields().forEachRemaining(entry -> {
                    String headerName = entry.getKey();
                    JsonNode headerData = entry.getValue();

                    Severity severity = Severity.valueOf(headerData.get("severity").asText());
                    String description = headerData.get("description").asText();
                    String purpose = headerData.get("purpose").asText();

                    requiredHeaders.put(headerName, new SecurityHeader(severity, description, purpose));
                });
            }

        } catch (Exception e) {
            logger.error("Failed to load security headers: {}", e.getMessage(), e);
        }
    }

    @Override
    protected void runTests(ScanContext context) throws Exception {
        loadPayloads();
        try (Response response = context.getHttpClient().get(context.getTargetUrl())) {

            for (Map.Entry<String, SecurityHeader> entry : requiredHeaders.entrySet()) {
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
