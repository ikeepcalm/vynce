package dev.ua.ikeepcalm.vynce.plugins;

import dev.ua.ikeepcalm.vynce.core.model.ScanContext;
import dev.ua.ikeepcalm.vynce.core.model.source.Severity;
import dev.ua.ikeepcalm.vynce.core.model.source.TestType;
import dev.ua.ikeepcalm.vynce.tests.BaseVulnerabilityTest;
import dev.ua.ikeepcalm.vynce.ui.ConsoleUI;
import okhttp3.Response;

import java.util.Arrays;
import java.util.Base64;
import java.util.List;


public class JWTTest extends BaseVulnerabilityTest {

    private static final List<String> JWT_HEADERS = Arrays.asList(
            "Authorization",
            "X-Access-Token",
            "X-Auth-Token",
            "X-JWT-Token"
    );

    @Override
    public TestType getTestType() {
        return TestType.CUSTOM;
    }

    @Override
    public String getTestName() {
        return "JWT Security";
    }

    @Override
    protected int estimateTestSteps(ScanContext context) {
        return JWT_HEADERS.size() + 1;
    }

    @Override
    protected void runTests(ScanContext context) throws Exception {
        try (Response response = context.getHttpClient().get(context.getTargetUrl())) {

            for (String headerName : JWT_HEADERS) {
                advanceProgress("Header: " + headerName);
                String headerValue = response.header(headerName);
                if (headerValue != null && looksLikeJWT(headerValue)) {
                    analyzeJWT(context, headerName, headerValue);
                }
            }

            advanceProgress("Response body");
            String body = context.getHttpClient().getBodyAsString(response);
            findJWTsInBody(context, body);
        }
    }

    private boolean looksLikeJWT(String value) {
        if (value.startsWith("Bearer ")) {
            value = value.substring(7);
        }

        String[] parts = value.split("\\.");
        return parts.length == 3 && isBase64Url(parts[0]) && isBase64Url(parts[1]);
    }

    private boolean isBase64Url(String str) {
        return str.matches("^[A-Za-z0-9_-]+$");
    }

    private void analyzeJWT(ScanContext context, String headerName, String jwtValue) {
        try {
            if (jwtValue.startsWith("Bearer ")) {
                jwtValue = jwtValue.substring(7);
            }

            String[] parts = jwtValue.split("\\.");
            if (parts.length != 3) {
                return;
            }

            String header = new String(Base64.getUrlDecoder().decode(parts[0]));

            if (header.contains("\"alg\"") && header.contains("\"none\"")) {
                addVulnerability(createVulnerability(
                        Severity.CRITICAL,
                        "JWT with 'none' Algorithm",
                        "JWT token uses 'none' algorithm, allowing signature bypass",
                        context.getTargetUrl(),
                        "Header: " + headerName
                ));
            }

            if (header.contains("\"HS256\"") || header.contains("\"HS384\"") || header.contains("\"HS512\"")) {
                addVulnerability(createVulnerability(
                        Severity.LOW,
                        "JWT with Weak HMAC Algorithm",
                        "JWT uses HMAC algorithm which may be vulnerable to key confusion attacks",
                        context.getTargetUrl(),
                        "Header: " + headerName
                ));
            }

            String payload = new String(Base64.getUrlDecoder().decode(parts[1]));

            if (!payload.contains("\"exp\"")) {
                addVulnerability(createVulnerability(
                        Severity.MEDIUM,
                        "JWT Missing Expiration",
                        "JWT token does not have an expiration claim, potentially valid forever",
                        context.getTargetUrl(),
                        "Header: " + headerName
                ));
            }

        } catch (Exception e) {
            ConsoleUI.debug("Error analyzing JWT: " + e.getMessage());
        }
    }

    private void findJWTsInBody(ScanContext context, String body) {
        String jwtPattern = "eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+";
        java.util.regex.Pattern pattern = java.util.regex.Pattern.compile(jwtPattern);
        java.util.regex.Matcher matcher = pattern.matcher(body);

        while (matcher.find()) {
            String jwt = matcher.group();
            addVulnerability(createVulnerability(
                    Severity.INFO,
                    "JWT Token Exposed in Response",
                    "JWT token found in response body, potential information disclosure",
                    context.getTargetUrl(),
                    "Token: " + jwt.substring(0, Math.min(30, jwt.length())) + "..."
            ));
            break;
        }
    }
}
