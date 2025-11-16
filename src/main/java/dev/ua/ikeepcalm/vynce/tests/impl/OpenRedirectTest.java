package dev.ua.ikeepcalm.vynce.tests.impl;

import dev.ua.ikeepcalm.vynce.core.model.ScanContext;
import dev.ua.ikeepcalm.vynce.core.model.Vulnerability;
import dev.ua.ikeepcalm.vynce.core.model.source.Severity;
import dev.ua.ikeepcalm.vynce.core.model.source.TestType;
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
    protected void runTests(ScanContext context) throws Exception {
        // Test URL parameters
        for (String url : context.getCrawler().getUrlsWithParams()) {
            Map<String, String> params = extractParams(url);
            for (String paramName : params.keySet()) {
                if (isRedirectParameter(paramName)) {
                    testOpenRedirect(context, url, paramName);
                }
            }
        }

        // Test discovered URLs for common redirect parameters
        for (String url : context.getCrawler().getAllUrls()) {
            for (String redirectParam : REDIRECT_PARAMS) {
                testOpenRedirectParameter(context, url, redirectParam);
            }
        }
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
                Response response = context.getHttpClient().get(testUrl, Collections.emptyMap());

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
            } catch (Exception e) {
                // Ignore errors
            }
        }
    }

    private void testOpenRedirectParameter(ScanContext context, String url, String paramName) {
        for (String payload : REDIRECT_PAYLOADS) {
            try {
                String testUrl = url + (url.contains("?") ? "&" : "?") + paramName + "=" + encodeUrl(payload);
                Response response = context.getHttpClient().get(testUrl, Collections.emptyMap());

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
