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

public class LdapInjectionTest extends BaseVulnerabilityTest {

    private List<String> ldapPayloads;
    private List<String> ldapErrorIndicators;

    @Override
    public TestType getTestType() {
        return TestType.LDAP;
    }

    @Override
    protected int estimateTestSteps(ScanContext context) {
        int count = 0;
        for (String url : context.getCrawler().getUniquePatternUrlsWithParams()) {
            if (WebCrawler.isStaticResource(url, true)) {
                continue;
            }
            Map<String, String> params = context.getCrawler().getParamsForUrl(url);
            count += params.size();
        }
        return count;
    }

    private void loadPayloads() {
        ldapPayloads = PayloadLoader.loadPayloads("ldap-injection.json", "payloads");
        ldapErrorIndicators = PayloadLoader.loadPayloads("ldap-injection.json", "error_indicators");
    }

    @Override
    protected void runTests(ScanContext context) {
        loadPayloads();
        for (String url : context.getCrawler().getUniquePatternUrlsWithParams()) {
            if (WebCrawler.isStaticResource(url, true)) {
                continue;
            }

            Map<String, String> params = context.getCrawler().getParamsForUrl(url);
            String testUrl = url + "?" + buildQueryString(params);
            for (String paramName : params.keySet()) {
                advanceProgress("Param: " + paramName);
                testLdapInjection(context, testUrl, paramName);
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

    private void testLdapInjection(ScanContext context, String url, String paramName) {
        for (String payload : ldapPayloads) {
            try {
                String testUrl = injectPayload(url, paramName, encodeUrl(payload));
                try (Response response = context.getHttpClient().get(testUrl, Collections.emptyMap())) {
                    if (response.isSuccessful()) {
                        String body = response.body() != null ? response.body().string() : "";

                        if (containsLdapErrorIndicators(body)) {
                            addVulnerability(createVulnerability(
                                    Severity.HIGH,
                                    "LDAP Injection",
                                    "Parameter '" + paramName + "' may be vulnerable to LDAP injection",
                                    url,
                                    payload
                            ));
                            break;
                        }

                        if (payload.equals("*") && body.length() > 1000) {
                            addVulnerability(createVulnerability(
                                    Severity.MEDIUM,
                                    "Possible LDAP Injection",
                                    "Parameter '" + paramName + "' shows different response with LDAP wildcard",
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

    private boolean containsLdapErrorIndicators(String body) {
        for (String indicator : ldapErrorIndicators) {
            if (body.contains(indicator)) {
                return true;
            }
        }
        return false;
    }
}
