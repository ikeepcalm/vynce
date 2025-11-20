package dev.ua.ikeepcalm.vynce.tests.impl;

import dev.ua.ikeepcalm.vynce.core.model.ScanContext;
import dev.ua.ikeepcalm.vynce.core.model.source.Severity;
import dev.ua.ikeepcalm.vynce.core.model.source.TestType;
import dev.ua.ikeepcalm.vynce.crawler.FormData;
import dev.ua.ikeepcalm.vynce.crawler.WebCrawler;
import dev.ua.ikeepcalm.vynce.tests.BaseVulnerabilityTest;
import dev.ua.ikeepcalm.vynce.utils.PayloadLoader;
import okhttp3.Response;

import java.util.Collections;
import java.util.List;
import java.util.Map;

public class SsrfTest extends BaseVulnerabilityTest {

    private List<String> ssrfPayloads;

    @Override
    public TestType getTestType() {
        return TestType.SSRF;
    }

    @Override
    protected int estimateTestSteps(ScanContext context) {
        int count = 0;
        for (String url : context.getCrawler().getUniquePatternUrlsWithParams()) {
            if (WebCrawler.isStaticResource(url, false)) {
                continue;
            }
            Map<String, String> params = context.getCrawler().getParamsForUrl(url);
            count += params.size();
        }
        for (FormData form : context.getCrawler().getDiscoveredForms()) {
            count += form.parameters().size();
        }
        return count;
    }

    private void loadPayloads() {
        ssrfPayloads = PayloadLoader.loadPayloads("ssrf.json", "payloads");
    }

    @Override
    protected void runTests(ScanContext context) {
        loadPayloads();
        for (String url : context.getCrawler().getUniquePatternUrlsWithParams()) {
            if (WebCrawler.isStaticResource(url, false)) {
                continue;
            }

            Map<String, String> params = context.getCrawler().getParamsForUrl(url);
            String testUrl = url + "?" + buildQueryString(params);
            for (String paramName : params.keySet()) {
                advanceProgress("Param: " + paramName);
                testSsrfInParameter(context, testUrl, paramName);
            }
        }

        for (FormData form : context.getCrawler().getDiscoveredForms()) {
            for (String paramName : form.parameters().keySet()) {
                advanceProgress("Form param: " + paramName);
                testSsrfInFormParam(context, form, paramName);
            }
        }
    }

    private void testSsrfInParameter(ScanContext context, String url, String paramName) {
        for (String payload : ssrfPayloads) {
            try {
                String testUrl = injectPayload(url, paramName, encodeUrl(payload));
                try (Response response = context.getHttpClient().get(testUrl, Collections.emptyMap())) {
                    if (response.isSuccessful()) {
                        String body = response.body() != null ? response.body().string() : "";

                        if (containsSsrfIndicators(body, payload)) {
                            addVulnerability(createVulnerability(
                                    Severity.HIGH,
                                    "Server-Side Request Forgery (SSRF)",
                                    "Parameter '" + paramName + "' may be vulnerable to SSRF",
                                    url,
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

    private void testSsrfInFormParam(ScanContext context, FormData form, String paramName) {
        for (String payload : ssrfPayloads) {
            try {
                Map<String, String> modifiedParams = form.parameters();
                modifiedParams.put(paramName, payload);

                if ("POST".equalsIgnoreCase(form.method())) {
                    try (Response response = context.getHttpClient().post(form.action(), modifiedParams, Collections.emptyMap())) {
                        if (response.isSuccessful()) {
                            String body = response.body() != null ? response.body().string() : "";

                            if (containsSsrfIndicators(body, payload)) {
                                addVulnerability(createVulnerability(
                                        Severity.HIGH,
                                        "Server-Side Request Forgery (SSRF)",
                                        "Form parameter '" + paramName + "' may be vulnerable to SSRF",
                                        form.action(),
                                        payload
                                ));
                                break;
                            }
                        }
                    }
                } else {
                    String testUrl = buildUrlWithParams(form.action(), modifiedParams);
                    try (Response response = context.getHttpClient().get(testUrl, Collections.emptyMap())) {
                        if (response.isSuccessful()) {
                            String body = response.body() != null ? response.body().string() : "";

                            if (containsSsrfIndicators(body, payload)) {
                                addVulnerability(createVulnerability(
                                        Severity.HIGH,
                                        "Server-Side Request Forgery (SSRF)",
                                        "Form parameter '" + paramName + "' may be vulnerable to SSRF",
                                        form.action(),
                                        payload
                                ));
                                break;
                            }
                        }
                    }
                }
            } catch (Exception ignored) {
            }
        }
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

    private boolean containsSsrfIndicators(String body, String payload) {
        if (payload.contains("169.254.169.254") && body.contains("ami-id")) {
            return true;
        }
        if (payload.contains("metadata.google.internal") && body.contains("project-id")) {
            return true;
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
