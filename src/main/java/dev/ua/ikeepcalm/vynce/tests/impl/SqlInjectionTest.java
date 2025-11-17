package dev.ua.ikeepcalm.vynce.tests.impl;

import dev.ua.ikeepcalm.vynce.core.model.ScanContext;
import dev.ua.ikeepcalm.vynce.core.model.source.Severity;
import dev.ua.ikeepcalm.vynce.core.model.source.TestType;
import dev.ua.ikeepcalm.vynce.tests.BaseVulnerabilityTest;
import dev.ua.ikeepcalm.vynce.ui.ConsoleUI;
import dev.ua.ikeepcalm.vynce.utils.PayloadLoader;
import okhttp3.Response;

import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

public class SqlInjectionTest extends BaseVulnerabilityTest {

    private List<String> errorPayloads;
    private List<String> booleanPayloads;
    private List<String> timePayloads;
    private List<String> errorPatterns;

    @Override
    public TestType getTestType() {
        return TestType.SQL;
    }

    @Override
    protected void runTests(ScanContext context) {
        loadPayloads();

        String url = context.getTargetUrl();

        if (!url.contains("?")) {
            ConsoleUI.error("No URL parameters found for SQL injection testing");
            return;
        }

        Map<String, String> params = extractParams(url);

        for (String paramName : params.keySet()) {
            ConsoleUI.debug("Testing parameter: " + " " + paramName);

            testErrorBased(context, url, paramName);

            testBooleanBased(context, url, paramName);

            testTimeBased(context, url, paramName);
        }
    }

    private void loadPayloads() {
        errorPayloads = PayloadLoader.loadPayloads("sql-injection.json", "error_based");
        booleanPayloads = PayloadLoader.loadPayloads("sql-injection.json", "boolean_based");
        timePayloads = PayloadLoader.loadPayloads("sql-injection.json", "time_based");
        errorPatterns = PayloadLoader.loadPayloads("sql-injection.json", "error_patterns");

        ConsoleUI.debug("Loaded error-based payloads" + " " + errorPayloads.size());
        ConsoleUI.debug("Loaded boolean-based payloads" + " " + booleanPayloads.size());
        ConsoleUI.debug("Loaded time-based payloads" + " " + timePayloads.size());
    }

    private void testErrorBased(ScanContext context, String url, String paramName) {
        for (String payload : errorPayloads) {
            try {
                String testUrl = injectPayload(url, paramName, encodeUrl(payload));

                try (Response response = context.getHttpClient().get(testUrl)) {
                    String body = context.getHttpClient().getBodyAsString(response);

                    if (containsSqlError(body)) {
                        addVulnerability(createVulnerability(
                                Severity.CRITICAL,
                                "Error-based SQL Injection detected in parameter '" + paramName + "'. " +
                                "Database error messages were found in the response, indicating SQL syntax issues.",
                                testUrl
                        ));
                        ConsoleUI.warning("SQL Injection found: with payload: " + " " + paramName + payload);
                        return;
                    }
                }

            } catch (Exception e) {
                ConsoleUI.debug("Error testing SQL injection: " + " " + e.getMessage());
            }
        }
    }

    private void testBooleanBased(ScanContext context, String url, String paramName) {
        try {
            try (Response baselineResponse = context.getHttpClient().get(url)) {
                String baselineBody = context.getHttpClient().getBodyAsString(baselineResponse);
                int baselineLength = baselineBody.length();

                String truePayload = "1' AND '1'='1";
                String trueUrl = injectPayload(url, paramName, encodeUrl(truePayload));

                try (Response trueResponse = context.getHttpClient().get(trueUrl)) {
                    String trueBody = context.getHttpClient().getBodyAsString(trueResponse);
                    int trueLength = trueBody.length();

                    String falsePayload = "1' AND '1'='2";
                    String falseUrl = injectPayload(url, paramName, encodeUrl(falsePayload));

                    try (Response falseResponse = context.getHttpClient().get(falseUrl)) {
                        String falseBody = context.getHttpClient().getBodyAsString(falseResponse);
                        int falseLength = falseBody.length();

                        if (Math.abs(trueLength - baselineLength) < 100 &&
                            Math.abs(falseLength - baselineLength) > 500) {
                            addVulnerability(createVulnerability(
                                    Severity.CRITICAL,
                                    "Boolean-based blind SQL Injection detected in parameter '" + paramName + "'. " +
                                    "The application responds differently to true and false SQL conditions.",
                                    url
                            ));
                            ConsoleUI.warning("Boolean-based SQL Injection found: " + " " + paramName);
                        }
                    }
                }
            }

        } catch (Exception e) {
            ConsoleUI.debug("Error testing boolean-based SQL injection: " + " " + e.getMessage());
        }
    }

    private void testTimeBased(ScanContext context, String url, String paramName) {
        String payload = timePayloads.isEmpty() ? "'; SELECT SLEEP(5)--" : timePayloads.getFirst();

        try {
            String testUrl = injectPayload(url, paramName, encodeUrl(payload));

            long startTime = System.currentTimeMillis();
            try (Response response = context.getHttpClient().get(testUrl)) {
                context.getHttpClient().getBodyAsString(response);
            }
            long duration = System.currentTimeMillis() - startTime;

            if (duration > 4000) {
                addVulnerability(createVulnerability(
                        Severity.CRITICAL,
                        "Time-based blind SQL Injection detected in parameter '" + paramName + "'. " +
                        "The application response was delayed by " + duration + "ms, indicating SQL command execution.",
                        testUrl
                ));
                ConsoleUI.warning("Time-based SQL Injection found: (delay: ms)" + " " + paramName + duration);
            }

        } catch (Exception e) {
            ConsoleUI.debug("Error testing time-based SQL injection: " + " " + e.getMessage());
        }
    }

    private boolean containsSqlError(String body) {
        for (String pattern : errorPatterns) {
            try {
                if (Pattern.compile(pattern, Pattern.CASE_INSENSITIVE).matcher(body).find()) {
                    ConsoleUI.debug("SQL error pattern matched: " + " " + pattern);
                    return true;
                }
            } catch (Exception e) {
                ConsoleUI.debug("Error checking pattern : " + " " + pattern, e.getMessage());
            }
        }
        return false;
    }
}
