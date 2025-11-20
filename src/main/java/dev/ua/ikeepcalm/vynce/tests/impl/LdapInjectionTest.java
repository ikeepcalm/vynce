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

public class LdapInjectionTest extends BaseVulnerabilityTest {

    private static final List<String> LDAP_PAYLOADS = Arrays.asList(
            "*",
            "*)(uid=*",
            "admin*",
            "admin)(&(password=*",
            "*)(|(uid=*",
            "*)(&(objectClass=*",
            "*))%00",
            "admin)(|(password=*",
            "*)(cn=*)(|(cn=*"
    );

    private static final List<String> LDAP_ERROR_INDICATORS = Arrays.asList(
            "javax.naming.NameNotFoundException",
            "LDAPException",
            "com.sun.jndi.ldap",
            "[LDAP:",
            "Invalid DN syntax",
            "LDAP: error code"
    );

    @Override
    public TestType getTestType() {
        return TestType.LDAP;
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
        for (String payload : LDAP_PAYLOADS) {
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
            } catch (Exception e) {
            }
        }
    }

    private boolean containsLdapErrorIndicators(String body) {
        for (String indicator : LDAP_ERROR_INDICATORS) {
            if (body.contains(indicator)) {
                return true;
            }
        }
        return false;
    }
}
