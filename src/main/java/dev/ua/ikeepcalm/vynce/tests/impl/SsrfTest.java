package dev.ua.ikeepcalm.vynce.tests.impl;

import dev.ua.ikeepcalm.vynce.core.model.ScanContext;
import dev.ua.ikeepcalm.vynce.core.model.Vulnerability;
import dev.ua.ikeepcalm.vynce.core.model.source.Severity;
import dev.ua.ikeepcalm.vynce.core.model.source.TestType;
import dev.ua.ikeepcalm.vynce.crawler.FormData;
import dev.ua.ikeepcalm.vynce.tests.BaseVulnerabilityTest;
import okhttp3.Response;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;

public class SsrfTest extends BaseVulnerabilityTest {

    private static final List<String> SSRF_PAYLOADS = Arrays.asList(
            "http://localhost",
            "http://127.0.0.1",
            "http://169.254.169.254/latest/meta-data/",  // AWS metadata
            "http://metadata.google.internal/computeMetadata/v1/",  // GCP metadata
            "http://[::1]",
            "http://0.0.0.0",
            "http://192.168.1.1",
            "file:///etc/passwd",
            "http://internal.company.local"
    );

    @Override
    public TestType getTestType() {
        return TestType.SSRF;
    }

    @Override
    protected void runTests(ScanContext context) throws Exception {
        // Test URL parameters
        for (String url : context.getCrawler().getUrlsWithParams()) {
            Map<String, String> params = extractParams(url);
            for (String paramName : params.keySet()) {
                testSsrfInParameter(context, url, paramName);
            }
        }

        // Test forms
        for (FormData form : context.getCrawler().getDiscoveredForms()) {
            testSsrfInForm(context, form);
        }
    }

    private void testSsrfInParameter(ScanContext context, String url, String paramName) {
        for (String payload : SSRF_PAYLOADS) {
            try {
                String testUrl = injectPayload(url, paramName, encodeUrl(payload));
                Response response = context.getHttpClient().get(testUrl, Collections.emptyMap());

                if (response.isSuccessful()) {
                    String body = response.body() != null ? response.body().string() : "";

                    // Check for indicators of SSRF
                    if (containsSsrfIndicators(body, payload)) {
                        addVulnerability(new Vulnerability(
                                Severity.HIGH,
                                "Server-Side Request Forgery (SSRF)",
                                "Parameter '" + paramName + "' may be vulnerable to SSRF",
                                url,
                                payload
                        ));
                        break;
                    }
                }
            } catch (Exception e) {
                // Ignore errors, they might indicate SSRF blocking
            }
        }
    }

    private void testSsrfInForm(ScanContext context, FormData form) {
        for (String paramName : form.getParameters().keySet()) {
            for (String payload : SSRF_PAYLOADS) {
                try {
                    Map<String, String> modifiedParams = form.getParameters();
                    modifiedParams.put(paramName, payload);

                    Response response;
                    if ("POST".equalsIgnoreCase(form.getMethod())) {
                        response = context.getHttpClient().post(form.getAction(), modifiedParams, Collections.emptyMap());
                    } else {
                        String testUrl = buildUrlWithParams(form.getAction(), modifiedParams);
                        response = context.getHttpClient().get(testUrl, Collections.emptyMap());
                    }

                    if (response.isSuccessful()) {
                        String body = response.body() != null ? response.body().string() : "";

                        if (containsSsrfIndicators(body, payload)) {
                            addVulnerability(new Vulnerability(
                                    Severity.HIGH,
                                    "Server-Side Request Forgery (SSRF)",
                                    "Form parameter '" + paramName + "' may be vulnerable to SSRF",
                                    form.getAction(),
                                    payload
                            ));
                            break;
                        }
                    }
                } catch (Exception e) {
                    // Ignore errors
                }
            }
        }
    }

    private boolean containsSsrfIndicators(String body, String payload) {
        // Check for various SSRF indicators
        if (payload.contains("169.254.169.254") && body.contains("ami-id")) {
            return true;  // AWS metadata
        }
        if (payload.contains("metadata.google.internal") && body.contains("project-id")) {
            return true;  // GCP metadata
        }
        if (payload.contains("localhost") || payload.contains("127.0.0.1")) {
            return body.contains("root:") || body.contains("daemon:") || body.contains("<!DOCTYPE");
        }
        return false;
    }

    private String buildUrlWithParams(String baseUrl, Map<String, String> params) {
        StringBuilder url = new StringBuilder(baseUrl);
        if (!params.isEmpty()) {
            url.append("?");
            params.forEach((key, value) -> url.append(key).append("=").append(encodeUrl(value)).append("&"));
            return url.substring(0, url.length() - 1);
        }
        return url.toString();
    }
}
