package dev.ua.ikeepcalm.vynce.tests.impl;

import dev.ua.ikeepcalm.vynce.core.model.ScanContext;
import dev.ua.ikeepcalm.vynce.core.model.source.Severity;
import dev.ua.ikeepcalm.vynce.core.model.source.TestType;
import dev.ua.ikeepcalm.vynce.tests.BaseVulnerabilityTest;
import okhttp3.Response;

import java.util.HashMap;
import java.util.Map;

public class CorsTest extends BaseVulnerabilityTest {

    private static final String[] TEST_ORIGINS = {
            "https://evil.com",
            "http://attacker.com",
            "null"
    };

    @Override
    public TestType getTestType() {
        return TestType.CORS;
    }

    @Override
    protected void runTests(ScanContext context) {
        testCorsConfiguration(context);
    }

    private void testCorsConfiguration(ScanContext context) {
        for (String testOrigin : TEST_ORIGINS) {
            try {
                Map<String, String> headers = new HashMap<>();
                headers.put("Origin", testOrigin);

                try (Response response = context.getHttpClient().get(context.getTargetUrl(), headers)) {
                    String acao = response.header("Access-Control-Allow-Origin");
                    String acac = response.header("Access-Control-Allow-Credentials");

                    if (acao != null) {
                        if ("*".equals(acao) && "true".equalsIgnoreCase(acac)) {
                            addVulnerability(createVulnerability(
                                    Severity.HIGH,
                                    "CORS Misconfiguration - Wildcard with Credentials",
                                    "Access-Control-Allow-Origin is set to * with credentials enabled",
                                    context.getTargetUrl(),
                                    "Origin: " + testOrigin
                            ));
                        }

                        if (acao.equals(testOrigin)) {
                            Severity severity = "true".equalsIgnoreCase(acac) ? Severity.HIGH : Severity.MEDIUM;
                            addVulnerability(createVulnerability(
                                    severity,
                                    "CORS Misconfiguration - Arbitrary Origin Reflected",
                                    "Access-Control-Allow-Origin reflects arbitrary origin: " + testOrigin,
                                    context.getTargetUrl(),
                                    "Origin: " + testOrigin
                            ));
                        }

                        if ("null".equals(acao) && testOrigin.equals("null")) {
                            addVulnerability(createVulnerability(
                                    Severity.MEDIUM,
                                    "CORS Misconfiguration - Null Origin Allowed",
                                    "Access-Control-Allow-Origin allows 'null' origin",
                                    context.getTargetUrl(),
                                    "Origin: null"
                            ));
                        }
                    }
                }
            } catch (Exception e) {
            }
        }

        checkMissingCorsHeaders(context);
    }

    private void checkMissingCorsHeaders(ScanContext context) {
        String[] apiPaths = {"/api", "/api/v1", "/graphql", "/rest"};

        for (String path : apiPaths) {
            String testUrl = context.getTargetUrl() + path;

            try (Response response = context.getHttpClient().get(testUrl, Map.of())) {
                String acao = response.header("Access-Control-Allow-Origin");

                if (acao == null && response.isSuccessful()) {
                    addVulnerability(createVulnerability(
                            Severity.INFO,
                            "Missing CORS Headers",
                            "API endpoint '" + path + "' does not set CORS headers",
                            testUrl,
                            null
                    ));
                }
            } catch (Exception e) {
            }
        }
    }
}
