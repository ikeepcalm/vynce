package dev.ua.ikeepcalm.vynce.plugins;

import dev.ua.ikeepcalm.vynce.core.model.ScanContext;
import dev.ua.ikeepcalm.vynce.core.model.Vulnerability;
import dev.ua.ikeepcalm.vynce.core.model.source.Severity;
import dev.ua.ikeepcalm.vynce.core.model.source.TestType;
import dev.ua.ikeepcalm.vynce.tests.BaseVulnerabilityTest;
import okhttp3.Response;

import java.util.*;

/**
 * Example custom plugin for testing JWT (JSON Web Token) security issues.
 * This demonstrates advanced plugin capabilities.
 */
public class JWTTest extends BaseVulnerabilityTest {

    private static final List<String> JWT_HEADERS = Arrays.asList(
            "Authorization",
            "X-Access-Token",
            "X-Auth-Token",
            "X-JWT-Token"
    );

    @Override
    public TestType getTestType() {
        // For custom tests, consider adding a custom TestType
        return TestType.HEADERS;  // Replace with custom TestType in production
    }

    @Override
    protected void runTests(ScanContext context) throws Exception {
        // Fetch the target URL to check for JWT in responses
        Response response = context.getHttpClient().get(context.getTargetUrl(), Collections.emptyMap());

        // Check response headers for JWT tokens
        for (String headerName : JWT_HEADERS) {
            String headerValue = response.header(headerName);
            if (headerValue != null && looksLikeJWT(headerValue)) {
                analyzeJWT(context, headerName, headerValue);
            }
        }

        // Check response body for embedded JWTs
        String body = response.body() != null ? response.body().string() : "";
        findJWTsInBody(context, body);
    }

    private boolean looksLikeJWT(String value) {
        // JWT format: header.payload.signature
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

            // Decode header (basic check)
            String header = new String(Base64.getUrlDecoder().decode(parts[0]));

            // Check for 'none' algorithm
            if (header.contains("\"alg\"") && header.contains("\"none\"")) {
                addVulnerability(createVulnerability(
                        Severity.CRITICAL,
                        "JWT with 'none' Algorithm",
                        "JWT token uses 'none' algorithm, allowing signature bypass",
                        context.getTargetUrl(),
                        "Header: " + headerName
                ));
            }

            // Check for weak algorithms
            if (header.contains("\"HS256\"") || header.contains("\"HS384\"") || header.contains("\"HS512\"")) {
                addVulnerability(createVulnerability(
                        Severity.LOW,
                        "JWT with Weak HMAC Algorithm",
                        "JWT uses HMAC algorithm which may be vulnerable to key confusion attacks",
                        context.getTargetUrl(),
                        "Header: " + headerName
                ));
            }

            // Decode payload to check expiration
            String payload = new String(Base64.getUrlDecoder().decode(parts[1]));

            // Check for missing expiration
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
            // Invalid JWT or decoding error, ignore
        }
    }

    private void findJWTsInBody(ScanContext context, String body) {
        // Simple regex to find potential JWTs in response body
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
            break;  // Report only once
        }
    }
}
