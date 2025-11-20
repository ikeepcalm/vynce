package dev.ua.ikeepcalm.vynce.tests.impl;

import dev.ua.ikeepcalm.vynce.core.model.ScanContext;
import dev.ua.ikeepcalm.vynce.core.model.source.Severity;
import dev.ua.ikeepcalm.vynce.core.model.source.TestType;
import dev.ua.ikeepcalm.vynce.crawler.FormData;
import dev.ua.ikeepcalm.vynce.tests.BaseVulnerabilityTest;
import dev.ua.ikeepcalm.vynce.utils.PayloadLoader;
import okhttp3.MediaType;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;

import java.util.List;

public class XxeTest extends BaseVulnerabilityTest {

    private List<String> xxePayloads;
    private List<String> xxeIndicators;

    @Override
    public TestType getTestType() {
        return TestType.XXE;
    }

    @Override
    protected int estimateTestSteps(ScanContext context) {
        int count = 0;
        for (FormData form : context.getCrawler().getDiscoveredForms()) {
            if ("POST".equalsIgnoreCase(form.method())) {
                count++;
            }
        }
        count += 4;
        return count;
    }

    private void loadPayloads() {
        xxePayloads = PayloadLoader.loadPayloads("xxe.json", "payloads");
        xxeIndicators = PayloadLoader.loadPayloads("xxe.json", "indicators");
    }

    @Override
    protected void runTests(ScanContext context) {
        loadPayloads();
        for (FormData form : context.getCrawler().getDiscoveredForms()) {
            if ("POST".equalsIgnoreCase(form.method())) {
                advanceProgress("Form: " + form.action());
                testXxeInForm(context, form);
            }
        }

        testXxeInEndpoints(context);
    }

    private void testXxeInForm(ScanContext context, FormData form) {
        for (String payload : xxePayloads) {
            try {
                Request request = new Request.Builder()
                        .url(form.action())
                        .post(RequestBody.create(payload, MediaType.parse("application/xml")))
                        .addHeader("Content-Type", "application/xml")
                        .build();

                try (Response response = context.getHttpClient().executeRequest(request)) {
                    if (response.isSuccessful()) {
                        String body = response.body() != null ? response.body().string() : "";

                        if (containsXxeIndicators(body)) {
                            addVulnerability(createVulnerability(
                                    Severity.HIGH,
                                    "XML External Entity (XXE) Injection",
                                    "Form at '" + form.action() + "' is vulnerable to XXE",
                                    form.action(),
                                    payload
                            ));
                            break;
                        }
                    }
                }
            } catch (Exception ignored) {
            }
        }
    }

    private void testXxeInEndpoints(ScanContext context) {
        String[] commonXmlEndpoints = {"/api/xml", "/upload", "/process", "/import"};

        for (String endpoint : commonXmlEndpoints) {
            advanceProgress("Endpoint: " + endpoint);
            String targetUrl = context.getTargetUrl() + endpoint;

            for (String payload : xxePayloads) {
                try {
                    Request request = new Request.Builder()
                            .url(targetUrl)
                            .post(RequestBody.create(payload, MediaType.parse("application/xml")))
                            .addHeader("Content-Type", "application/xml")
                            .build();

                    try (Response response = context.getHttpClient().executeRequest(request)) {
                        if (response.isSuccessful()) {
                            String body = response.body() != null ? response.body().string() : "";

                            if (containsXxeIndicators(body)) {
                                addVulnerability(createVulnerability(
                                        Severity.HIGH,
                                        "XML External Entity (XXE) Injection",
                                        "Endpoint '" + endpoint + "' is vulnerable to XXE",
                                        targetUrl,
                                        payload
                                ));
                                break;
                            }
                        }
                    }
                } catch (Exception ignored) {
                }
            }
        }
    }

    private boolean containsXxeIndicators(String body) {
        for (String indicator : xxeIndicators) {
            if (body.contains(indicator)) {
                return true;
            }
        }
        return false;
    }
}
