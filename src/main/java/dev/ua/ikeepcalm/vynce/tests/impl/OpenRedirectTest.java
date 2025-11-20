package dev.ua.ikeepcalm.vynce.tests.impl;

import dev.ua.ikeepcalm.vynce.core.model.ScanContext;
import dev.ua.ikeepcalm.vynce.core.model.source.Severity;
import dev.ua.ikeepcalm.vynce.core.model.source.TestType;
import dev.ua.ikeepcalm.vynce.crawler.WebCrawler;
import dev.ua.ikeepcalm.vynce.tests.BaseVulnerabilityTest;
import okhttp3.Response;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;

public class OpenRedirectTest extends BaseVulnerabilityTest {

    private static final List<String> REDIRECT_PAYLOADS = Arrays.asList(
            "https://evil.com",
            "http://attacker.com",
            "//evil.com",
            "//evil.com/",
            "///evil.com",
            "////evil.com",
            "https:evil.com",
            "//google.com",
            "javascript:alert(1)",
            "/\\evil.com",
            "https://evil.com@target.com"
    );

    private static final List<String> REDIRECT_PARAMS = Arrays.asList(
            "url", "redirect", "next", "return", "returnUrl", "return_url",
            "redirect_uri", "continue", "dest", "destination", "redir",
            "redirect_url", "checkout_url", "goto", "target"
    );

    @Override
    public TestType getTestType() {
        return TestType.OPEN_REDIRECT;
    }

    @Override
    protected int estimateTestSteps(ScanContext context) {
        int count = 0;

        for (String url : context.getCrawler().getUniquePatternUrlsWithParams()) {
            if (WebCrawler.isStaticResource(url, true)) {
                continue;
            }
            Map<String, String> params = context.getCrawler().getParamsForUrl(url);
            for (String paramName : params.keySet()) {
                if (isRedirectParameter(paramName)) {
                    count++;
                }
            }
        }

        for (String url : context.getCrawler().getUniquePatternUrls()) {
            if (!WebCrawler.isStaticResource(url, true)) {
                count += REDIRECT_PARAMS.size();
            }
        }

        return count;
    }

    @Override
    protected void runTests(ScanContext context) {
        for (String url : context.getCrawler().getUniquePatternUrlsWithParams()) {
            if (WebCrawler.isStaticResource(url, true)) {
                continue;
            }

            Map<String, String> params = context.getCrawler().getParamsForUrl(url);
            String testUrl = url + "?" + buildQueryString(params);
            for (String paramName : params.keySet()) {
                if (isRedirectParameter(paramName)) {
                    advanceProgress("Param: " + paramName);
                    testOpenRedirect(context, testUrl, paramName);
                }
            }
        }

        for (String url : context.getCrawler().getUniquePatternUrls()) {
            if (WebCrawler.isStaticResource(url, true)) {
                continue;
            }

            for (String redirectParam : REDIRECT_PARAMS) {
                advanceProgress("Testing: " + redirectParam);
                testOpenRedirectParameter(context, url, redirectParam);
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

    private boolean isRedirectParameter(String paramName) {
        String lowerParam = paramName.toLowerCase();
        for (String redirectParam : REDIRECT_PARAMS) {
            if (lowerParam.contains(redirectParam)) {
                return true;
            }
        }
        return false;
    }

    private void testOpenRedirect(ScanContext context, String url, String paramName) {
        for (String payload : REDIRECT_PAYLOADS) {
            try {
                String testUrl = injectPayload(url, paramName, encodeUrl(payload));
                try (Response response = context.getHttpClient().get(testUrl, Collections.emptyMap())) {
                    if (isRedirect(response)) {
                        String location = response.header("Location");

                        if (location != null && (location.contains("evil.com") || location.contains("attacker.com") || location.contains("google.com"))) {
                            addVulnerability(createVulnerability(
                                    Severity.MEDIUM,
                                    "Open Redirect",
                                    "Parameter '" + paramName + "' is vulnerable to open redirect",
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

    private void testOpenRedirectParameter(ScanContext context, String url, String paramName) {
        for (String payload : REDIRECT_PAYLOADS) {
            try {
                String testUrl = url + (url.contains("?") ? "&" : "?") + paramName + "=" + encodeUrl(payload);
                try (Response response = context.getHttpClient().get(testUrl, Collections.emptyMap())) {
                    if (isRedirect(response)) {
                        String location = response.header("Location");

                        if (location != null && (location.contains("evil.com") || location.contains("attacker.com") || location.contains("google.com"))) {
                            addVulnerability(createVulnerability(
                                    Severity.MEDIUM,
                                    "Open Redirect",
                                    "Parameter '" + paramName + "' is vulnerable to open redirect",
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

    private boolean isRedirect(Response response) {
        int code = response.code();
        return code == 301 || code == 302 || code == 303 || code == 307 || code == 308;
    }
}
