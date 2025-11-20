package dev.ua.ikeepcalm.vynce.tests.impl;

import dev.ua.ikeepcalm.vynce.core.model.ScanContext;
import dev.ua.ikeepcalm.vynce.core.model.source.Severity;
import dev.ua.ikeepcalm.vynce.core.model.source.TestType;
import dev.ua.ikeepcalm.vynce.crawler.FormData;
import dev.ua.ikeepcalm.vynce.tests.BaseVulnerabilityTest;
import dev.ua.ikeepcalm.vynce.ui.ConsoleUI;
import dev.ua.ikeepcalm.vynce.utils.PayloadLoader;
import okhttp3.Response;

import java.util.HashMap;
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

        List<String> urlsWithParams = context.getCrawler().getUniquePatternUrlsWithParams();

        if (urlsWithParams.isEmpty()) {
            ConsoleUI.error("No URL parameters found for SQL injection testing");
            return;
        }

        ConsoleUI.debug("Found " + urlsWithParams.size() + " URLs with parameters to test");
        ConsoleUI.debug("URLs discovered by crawler:");
        for (String discoveredUrl : urlsWithParams) {
            Map<String, String> discoveredParams = context.getCrawler().getParamsForUrl(discoveredUrl);
            ConsoleUI.debug("  - " + discoveredUrl + " with params: " + discoveredParams.keySet());
        }

        for (String url : urlsWithParams) {
            ConsoleUI.debug("Processing URL: " + url);
            Map<String, String> params = context.getCrawler().getParamsForUrl(url);
            ConsoleUI.debug("Extracted " + params.size() + " parameters: " + params.keySet());

            if (params.isEmpty()) {
                ConsoleUI.debug("WARNING: No parameters extracted from URL: " + url);
                continue;
            }

            for (String paramName : params.keySet()) {
                ConsoleUI.debug("Testing parameter: " + paramName + " in URL: " + url);

                String testUrl = url + "?" + buildQueryString(params);

                testErrorBased(context, testUrl, paramName);

                testBooleanBased(context, testUrl, paramName);

                testTimeBased(context, testUrl, paramName);
            }
        }

        List<FormData> forms = context.getCrawler().getDiscoveredForms();
        ConsoleUI.debug("Found " + forms.size() + " forms to test");

        for (FormData form : forms) {
            ConsoleUI.debug("Processing form: " + form.method() + " " + form.action() +
                          " with params: " + form.parameters().keySet());

            for (String paramName : form.parameters().keySet()) {
                ConsoleUI.debug("Testing form parameter: " + paramName);

                if ("GET".equalsIgnoreCase(form.method())) {
                    String testUrl = form.action() + "?" + buildQueryString(form.parameters());
                    testErrorBased(context, testUrl, paramName);
                    testBooleanBased(context, testUrl, paramName);
                    testTimeBased(context, testUrl, paramName);
                } else {
                    testErrorBasedPost(context, form, paramName);
                    testBooleanBasedPost(context, form, paramName);
                    testTimeBasedPost(context, form, paramName);
                }
            }
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

    private String buildQueryString(Map<String, String> params) {
        StringBuilder sb = new StringBuilder();
        for (Map.Entry<String, String> entry : params.entrySet()) {
            if (!sb.isEmpty()) {
                sb.append("&");
            }
            sb.append(entry.getKey()).append("=").append(entry.getValue());
        }
        return sb.toString();
    }

    private void testErrorBased(ScanContext context, String url, String paramName) {
        ConsoleUI.debug("=== Starting error-based test for parameter: " + paramName + " ===");
        ConsoleUI.debug("Total error payloads to test: " + errorPayloads.size());

        for (String payload : errorPayloads) {
            try {
                String testUrl = injectPayload(url, paramName, encodeUrl(payload));
                ConsoleUI.debug("Testing error-based payload on " + paramName + ": " + payload);
                ConsoleUI.debug("Test URL: " + testUrl);

                try (Response response = context.getHttpClient().get(testUrl)) {
                    String body = context.getHttpClient().getBodyAsString(response);
                    ConsoleUI.debug("Response code: " + response.code() + ", body length: " + body.length());

                    if (containsSqlError(body)) {
                        addVulnerability(createVulnerability(
                                Severity.CRITICAL,
                                "Error-based SQL Injection detected in parameter '" + paramName + "'. " +
                                "Database error messages were found in the response, indicating SQL syntax issues.",
                                testUrl
                        ));
                        ConsoleUI.warning("SQL Injection found with payload: " + paramName + " = " + payload);
                        return;
                    }
                }

            } catch (Exception e) {
                ConsoleUI.debug("Error testing SQL injection on " + paramName + ": " + e.getMessage());
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

    private void testErrorBasedPost(ScanContext context, FormData form, String paramName) {
        ConsoleUI.debug("=== Starting error-based POST test for parameter: " + paramName + " ===");

        for (String payload : errorPayloads) {
            try {
                Map<String, String> testParams = new HashMap<>(form.parameters());
                testParams.put(paramName, payload);

                ConsoleUI.debug("Testing error-based POST payload on " + paramName + ": " + payload);

                try (Response response = context.getHttpClient().post(form.action(), testParams)) {
                    String body = context.getHttpClient().getBodyAsString(response);
                    ConsoleUI.debug("Response code: " + response.code() + ", body length: " + body.length());

                    if (containsSqlError(body)) {
                        addVulnerability(createVulnerability(
                                Severity.CRITICAL,
                                "Error-based SQL Injection detected in POST parameter '" + paramName + "'. " +
                                "Database error messages were found in the response, indicating SQL syntax issues.",
                                form.action() + " (POST)"
                        ));
                        ConsoleUI.warning("SQL Injection found with POST payload: " + paramName + " = " + payload);
                        return;
                    }
                }

            } catch (Exception e) {
                ConsoleUI.debug("Error testing SQL injection on POST " + paramName + ": " + e.getMessage());
            }
        }
    }

    private void testBooleanBasedPost(ScanContext context, FormData form, String paramName) {
        try {
            try (Response baselineResponse = context.getHttpClient().post(form.action(), form.parameters())) {
                String baselineBody = context.getHttpClient().getBodyAsString(baselineResponse);
                int baselineLength = baselineBody.length();

                Map<String, String> trueParams = new HashMap<>(form.parameters());
                trueParams.put(paramName, "1' AND '1'='1");

                try (Response trueResponse = context.getHttpClient().post(form.action(), trueParams)) {
                    String trueBody = context.getHttpClient().getBodyAsString(trueResponse);
                    int trueLength = trueBody.length();

                    Map<String, String> falseParams = new HashMap<>(form.parameters());
                    falseParams.put(paramName, "1' AND '1'='2");

                    try (Response falseResponse = context.getHttpClient().post(form.action(), falseParams)) {
                        String falseBody = context.getHttpClient().getBodyAsString(falseResponse);
                        int falseLength = falseBody.length();

                        if (Math.abs(trueLength - baselineLength) < 100 &&
                            Math.abs(falseLength - baselineLength) > 500) {
                            addVulnerability(createVulnerability(
                                    Severity.CRITICAL,
                                    "Boolean-based blind SQL Injection detected in POST parameter '" + paramName + "'. " +
                                    "The application responds differently to true and false SQL conditions.",
                                    form.action() + " (POST)"
                            ));
                            ConsoleUI.warning("Boolean-based SQL Injection found in POST: " + paramName);
                        }
                    }
                }
            }

        } catch (Exception e) {
            ConsoleUI.debug("Error testing boolean-based SQL injection on POST: " + e.getMessage());
        }
    }

    private void testTimeBasedPost(ScanContext context, FormData form, String paramName) {
        String payload = timePayloads.isEmpty() ? "'; SELECT SLEEP(5)--" : timePayloads.getFirst();

        try {
            Map<String, String> testParams = new HashMap<>(form.parameters());
            testParams.put(paramName, payload);

            long startTime = System.currentTimeMillis();
            try (Response response = context.getHttpClient().post(form.action(), testParams)) {
                context.getHttpClient().getBodyAsString(response);
            }
            long duration = System.currentTimeMillis() - startTime;

            if (duration > 4000) {
                addVulnerability(createVulnerability(
                        Severity.CRITICAL,
                        "Time-based blind SQL Injection detected in POST parameter '" + paramName + "'. " +
                        "The application response was delayed by " + duration + "ms, indicating SQL command execution.",
                        form.action() + " (POST)"
                ));
                ConsoleUI.warning("Time-based SQL Injection found in POST: " + paramName + " (delay: " + duration + "ms)");
            }

        } catch (Exception e) {
            ConsoleUI.debug("Error testing time-based SQL injection on POST: " + e.getMessage());
        }
    }

    private boolean containsSqlError(String body) {
        for (String pattern : errorPatterns) {
            try {
                if (Pattern.compile(pattern, Pattern.CASE_INSENSITIVE).matcher(body).find()) {
                    ConsoleUI.debug("SQL error pattern matched: " + pattern);
                    return true;
                }
            } catch (Exception e) {
                ConsoleUI.debug("Error checking pattern: " + pattern + " - " + e.getMessage());
            }
        }

        String lowerBody = body.toLowerCase();
        if (lowerBody.contains("sql") && (
                lowerBody.contains("error") ||
                lowerBody.contains("syntax") ||
                lowerBody.contains("exception") ||
                lowerBody.contains("warning"))) {
            ConsoleUI.debug("Generic SQL error detected in response body");
            return true;
        }

        return false;
    }
}
