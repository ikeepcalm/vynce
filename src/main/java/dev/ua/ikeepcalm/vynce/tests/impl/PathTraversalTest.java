package dev.ua.ikeepcalm.vynce.tests.impl;

import dev.ua.ikeepcalm.vynce.core.model.ScanContext;
import dev.ua.ikeepcalm.vynce.core.model.source.Severity;
import dev.ua.ikeepcalm.vynce.core.model.source.TestType;
import dev.ua.ikeepcalm.vynce.tests.BaseVulnerabilityTest;
import okhttp3.Response;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;

public class PathTraversalTest extends BaseVulnerabilityTest {

    private static final List<String> PATH_TRAVERSAL_PAYLOADS = Arrays.asList(
            "../../../etc/passwd",
            "..\\..\\..\\windows\\win.ini",
            "....//....//....//etc/passwd",
            "..%2F..%2F..%2Fetc%2Fpasswd",
            "..%252F..%252F..%252Fetc%252Fpasswd",
            "..%c0%af..%c0%af..%c0%afetc/passwd",
            "/etc/passwd",
            "file:///etc/passwd",
            "C:\\windows\\win.ini",
            "../../../../../../etc/passwd",
            "..\\..\\..\\..\\..\\..\\..\\..\\windows\\win.ini"
    );

    private static final List<String> UNIX_INDICATORS = Arrays.asList(
            "root:x:", "daemon:", "bin:", "sys:", "/bin/bash", "/bin/sh"
    );

    private static final List<String> WINDOWS_INDICATORS = Arrays.asList(
            "[fonts]", "[extensions]", "for 16-bit app support", "MAPI="
    );

    @Override
    public TestType getTestType() {
        return TestType.PATH_TRAVERSAL;
    }

    @Override
    protected void runTests(ScanContext context) {
        for (String url : context.getCrawler().getUrlsWithParams()) {
            Map<String, String> params = extractParams(url);
            for (String paramName : params.keySet()) {
                testPathTraversal(context, url, paramName);
            }
        }
    }

    private void testPathTraversal(ScanContext context, String url, String paramName) {
        for (String payload : PATH_TRAVERSAL_PAYLOADS) {
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
        for (String indicator : UNIX_INDICATORS) {
            if (body.contains(indicator)) {
                return true;
            }
        }

        for (String indicator : WINDOWS_INDICATORS) {
            if (body.contains(indicator)) {
                return true;
            }
        }

        return false;
    }
}
