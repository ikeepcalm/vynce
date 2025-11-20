package dev.ua.ikeepcalm.vynce.tests.impl;

import dev.ua.ikeepcalm.vynce.core.model.ScanContext;
import dev.ua.ikeepcalm.vynce.core.model.source.Severity;
import dev.ua.ikeepcalm.vynce.core.model.source.TestType;
import dev.ua.ikeepcalm.vynce.crawler.WebCrawler;
import dev.ua.ikeepcalm.vynce.tests.BaseVulnerabilityTest;
import dev.ua.ikeepcalm.vynce.utils.PayloadLoader;
import okhttp3.Response;

import java.util.Collections;
import java.util.List;
import java.util.Map;

public class PathTraversalTest extends BaseVulnerabilityTest {

    private List<String> pathTraversalPayloads;
    private List<String> unixIndicators;
    private List<String> windowsIndicators;

    @Override
    public TestType getTestType() {
        return TestType.PATH_TRAVERSAL;
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
        return count;
    }

    private void loadPayloads() {
        pathTraversalPayloads = PayloadLoader.loadPayloads("path-traversal.json", "payloads");
        unixIndicators = PayloadLoader.loadPayloads("path-traversal.json", "unix_indicators");
        windowsIndicators = PayloadLoader.loadPayloads("path-traversal.json", "windows_indicators");
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
                testPathTraversal(context, testUrl, paramName);
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

    private void testPathTraversal(ScanContext context, String url, String paramName) {
        for (String payload : pathTraversalPayloads) {
            try {
                String testUrl = injectPayload(url, paramName, payload);
                try (Response response = context.getHttpClient().get(testUrl, Collections.emptyMap())) {
                    if (response.isSuccessful()) {
                        String body = response.body() != null ? response.body().string() : "";

                        if (containsPathTraversalIndicators(body)) {
                            addVulnerability(createVulnerability(
                                    Severity.HIGH,
                                    "Path Traversal",
                                    "Parameter '" + paramName + "' is vulnerable to path traversal",
                                    url,
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

    private boolean containsPathTraversalIndicators(String body) {
        for (String indicator : unixIndicators) {
            if (body.contains(indicator)) {
                return true;
            }
        }

        for (String indicator : windowsIndicators) {
            if (body.contains(indicator)) {
                return true;
            }
        }

        return false;
    }
}
