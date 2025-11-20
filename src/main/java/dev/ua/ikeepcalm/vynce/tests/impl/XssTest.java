package dev.ua.ikeepcalm.vynce.tests.impl;
import dev.ua.ikeepcalm.vynce.ui.ConsoleUI;

import dev.ua.ikeepcalm.vynce.core.model.ScanContext;
import dev.ua.ikeepcalm.vynce.core.model.source.Severity;
import dev.ua.ikeepcalm.vynce.core.model.source.TestType;
import dev.ua.ikeepcalm.vynce.crawler.FormData;
import dev.ua.ikeepcalm.vynce.tests.BaseVulnerabilityTest;
import dev.ua.ikeepcalm.vynce.utils.PayloadLoader;
import okhttp3.Response;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
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

        List<String> urlsWithParams = context.getCrawler().getUniquePatternUrlsWithParams();
        ConsoleUI.debug("Found " + urlsWithParams.size() + " URLs with parameters to test for XSS");

        for (String url : urlsWithParams) {
            Map<String, String> params = context.getCrawler().getParamsForUrl(url);
            if (!params.isEmpty()) {
                String testUrl = url + "?" + buildQueryString(params);
                testReflectedXss(context, testUrl);
            }
        }

        List<FormData> forms = context.getCrawler().getDiscoveredForms();
        ConsoleUI.debug("Found " + forms.size() + " forms to test for XSS");

        for (FormData form : forms) {
            ConsoleUI.debug("Testing form: " + form.method() + " " + form.action());

            if ("GET".equalsIgnoreCase(form.method())) {
                String testUrl = form.action() + "?" + buildQueryString(form.parameters());
                testReflectedXss(context, testUrl);
            } else {
                testReflectedXssPost(context, form);
            }
        }

        testPageXss(context, context.getTargetUrl());
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

    private void testReflectedXssPost(ScanContext context, FormData form) {
        for (String paramName : form.parameters().keySet()) {
            ConsoleUI.debug("Testing POST parameter for XSS: " + paramName);

            for (String payload : basicPayloads) {
                if (testPayloadPost(context, form, paramName, payload)) {
                    addVulnerability(createVulnerability(
                            Severity.HIGH,
                            "Reflected XSS detected in POST parameter '" + paramName + "'. " +
                                    "User input is reflected in the HTML response without proper encoding.",
                            form.action() + " (POST)"
                    ));
                    ConsoleUI.warning("Reflected XSS found in POST parameter: " + paramName);
                    return;
                }
            }

            for (String payload : attributePayloads) {
                if (testPayloadPost(context, form, paramName, payload)) {
                    addVulnerability(createVulnerability(
                            Severity.HIGH,
                            "Attribute-based XSS detected in POST parameter '" + paramName + "'. " +
                                    "User input is reflected inside HTML attributes without proper escaping.",
                            form.action() + " (POST)"
                    ));
                    ConsoleUI.warning("Attribute-based XSS found in POST parameter: " + paramName);
                    return;
                }
            }

            for (String payload : jsPayloads) {
                if (testJsPayloadPost(context, form, paramName, payload)) {
                    addVulnerability(createVulnerability(
                            Severity.HIGH,
                            "JavaScript context XSS detected in POST parameter '" + paramName + "'. " +
                                    "User input is reflected inside JavaScript code.",
                            form.action() + " (POST)"
                    ));
                    ConsoleUI.warning("JavaScript XSS found in POST parameter: " + paramName);
                    return;
                }
            }
        }
    }

    private boolean testPayloadPost(ScanContext context, FormData form, String paramName, String payload) {
        try {
            Map<String, String> testParams = new HashMap<>(form.parameters());
            testParams.put(paramName, payload);

            try (Response response = context.getHttpClient().post(form.action(), testParams)) {
                String body = context.getHttpClient().getBodyAsString(response);

                if (isReflectedUnsafe(body, payload)) {
                    ConsoleUI.debug("XSS payload reflected in POST: " + payload);
                    return true;
                }
            }

        } catch (Exception e) {
            ConsoleUI.debug("Error testing XSS POST payload: " + e.getMessage());
        }

        return false;
    }

    private boolean testJsPayloadPost(ScanContext context, FormData form, String paramName, String payload) {
        try {
            Map<String, String> testParams = new HashMap<>(form.parameters());
            testParams.put(paramName, payload);

            try (Response response = context.getHttpClient().post(form.action(), testParams)) {
                String body = context.getHttpClient().getBodyAsString(response);

                if (body.contains(payload) || body.contains(payload.replace("javascript:", ""))) {
                    ConsoleUI.debug("JavaScript XSS payload reflected in POST: " + payload);
                    return true;
                }
            }

        } catch (Exception e) {
            ConsoleUI.debug("Error testing JavaScript XSS POST: " + e.getMessage());
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
