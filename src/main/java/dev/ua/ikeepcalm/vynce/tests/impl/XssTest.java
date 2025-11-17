package dev.ua.ikeepcalm.vynce.tests.impl;
import dev.ua.ikeepcalm.vynce.ui.ConsoleUI;

import dev.ua.ikeepcalm.vynce.core.model.ScanContext;
import dev.ua.ikeepcalm.vynce.core.model.source.Severity;
import dev.ua.ikeepcalm.vynce.core.model.source.TestType;
import dev.ua.ikeepcalm.vynce.tests.BaseVulnerabilityTest;
import dev.ua.ikeepcalm.vynce.utils.PayloadLoader;
import okhttp3.Response;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

public class XssTest extends BaseVulnerabilityTest {

    private List<String> basicPayloads;
    private List<String> attributePayloads;
    private List<String> jsPayloads;

    @Override
    public TestType getTestType() {
        return TestType.XSS;
    }

    @Override
    protected void runTests(ScanContext context) {
        loadPayloads();

        String url = context.getTargetUrl();

        if (url.contains("?")) {
            testReflectedXss(context, url);
        }

        testPageXss(context, url);
    }

    private void loadPayloads() {
        basicPayloads = PayloadLoader.loadPayloads("xss-vectors.json", "basic");
        attributePayloads = PayloadLoader.loadPayloads("xss-vectors.json", "attribute_based");
        jsPayloads = PayloadLoader.loadPayloads("xss-vectors.json", "javascript");

        ConsoleUI.debug("Loaded basic XSS payloads" + " " + basicPayloads.size());
        ConsoleUI.debug("Loaded attribute-based XSS payloads" + " " + attributePayloads.size());
        ConsoleUI.debug("Loaded JavaScript XSS payloads" + " " + jsPayloads.size());
    }

    private void testReflectedXss(ScanContext context, String url) {
        Map<String, String> params = extractParams(url);

        for (String paramName : params.keySet()) {
            ConsoleUI.debug("Testing parameter for XSS: " + " " + paramName);

            for (String payload : basicPayloads) {
                if (testPayload(context, url, paramName, payload)) {
                    addVulnerability(createVulnerability(
                            Severity.HIGH,
                            "Reflected XSS detected in parameter '" + paramName + "'. " +
                                    "User input is reflected in the HTML response without proper encoding.",
                            url
                    ));
                    ConsoleUI.warning("Reflected XSS found in parameter: " + " " + paramName);
                    return;
                }
            }

            for (String payload : attributePayloads) {
                if (testPayload(context, url, paramName, payload)) {
                    addVulnerability(createVulnerability(
                            Severity.HIGH,
                            "Attribute-based XSS detected in parameter '" + paramName + "'. " +
                                    "User input is reflected inside HTML attributes without proper escaping.",
                            url
                    ));
                    ConsoleUI.warning("Attribute-based XSS found in parameter: " + " " + paramName);
                    return;
                }
            }

            for (String payload : jsPayloads) {
                if (testJsPayload(context, url, paramName, payload)) {
                    addVulnerability(createVulnerability(
                            Severity.HIGH,
                            "JavaScript context XSS detected in parameter '" + paramName + "'. " +
                                    "User input is reflected inside JavaScript code.",
                            url
                    ));
                    ConsoleUI.warning("JavaScript XSS found in parameter: " + " " + paramName);
                    return;
                }
            }
        }
    }

    private boolean testPayload(ScanContext context, String url, String paramName, String payload) {
        try {
            String encodedPayload = URLEncoder.encode(payload, StandardCharsets.UTF_8);
            String testUrl = injectPayload(url, paramName, encodedPayload);

            try (Response response = context.getHttpClient().get(testUrl)) {
                String body = context.getHttpClient().getBodyAsString(response);

                if (isReflectedUnsafe(body, payload)) {
                    ConsoleUI.debug("XSS payload reflected: " + " " + payload);
                    return true;
                }
            }

        } catch (Exception e) {
            ConsoleUI.debug("Error testing XSS payload: " + " " + e.getMessage());
        }

        return false;
    }

    private boolean testJsPayload(ScanContext context, String url, String paramName, String payload) {
        try {
            String testUrl = injectPayload(url, paramName, payload);

            try (Response response = context.getHttpClient().get(testUrl)) {
                String body = context.getHttpClient().getBodyAsString(response);

                if (body.contains(payload) || body.contains(payload.replace("javascript:", ""))) {
                    ConsoleUI.debug("JavaScript XSS payload reflected: " + " " + payload);
                    return true;
                }
            }

        } catch (Exception e) {
            ConsoleUI.debug("Error testing JavaScript XSS: " + " " + e.getMessage());
        }

        return false;
    }

    private boolean isReflectedUnsafe(String body, String payload) {
        if (body.contains(payload)) {
            return true;
        }

        String[] dangerousPatterns = {
                "<script>",
                "onerror=",
                "onload=",
                "onclick=",
                "onmouseover=",
                "javascript:",
                "<svg",
                "<img",
                "<iframe"
        };

        for (String pattern : dangerousPatterns) {
            if (payload.toLowerCase().contains(pattern.toLowerCase()) &&
                    body.toLowerCase().contains(pattern.toLowerCase())) {
                return true;
            }
        }

        return false;
    }

    private void testPageXss(ScanContext context, String url) {
        try {
            try (Response response = context.getHttpClient().get(url)) {
                String body = context.getHttpClient().getBodyAsString(response);

                checkForDangerousPatterns(body, url);
            }

        } catch (Exception e) {
            ConsoleUI.debug("Error testing page XSS: " + " " + e.getMessage());
        }
    }

    private void checkForDangerousPatterns(String body, String url) {
        if (body.matches("(?i).*eval\\s*\\(.*\\).*")) {
            addVulnerability(createVulnerability(
                    Severity.MEDIUM,
                    "Use of eval() detected in JavaScript code, which can lead to code injection vulnerabilities.",
                    url
            ));
        }

        if (body.matches("(?i).*innerHTML\\s*=.*")) {
            addVulnerability(createVulnerability(
                    Severity.LOW,
                    "Use of innerHTML detected. If user input is assigned to innerHTML without sanitization, XSS is possible.",
                    url
            ));
        }

        if (body.matches("(?i).*document\\.write\\s*\\(.*\\).*")) {
            addVulnerability(createVulnerability(
                    Severity.LOW,
                    "Use of document.write() detected, which can be exploited for XSS if user input is involved.",
                    url
            ));
        }
    }
}
