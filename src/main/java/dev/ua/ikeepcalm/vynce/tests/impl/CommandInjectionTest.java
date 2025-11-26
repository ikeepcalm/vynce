package dev.ua.ikeepcalm.vynce.tests.impl;

import dev.ua.ikeepcalm.vynce.core.model.ScanContext;
import dev.ua.ikeepcalm.vynce.core.model.source.Severity;
import dev.ua.ikeepcalm.vynce.core.model.source.TestType;
import dev.ua.ikeepcalm.vynce.crawler.WebCrawler;
import dev.ua.ikeepcalm.vynce.tests.BaseVulnerabilityTest;
import dev.ua.ikeepcalm.vynce.ui.ConsoleUI;
import dev.ua.ikeepcalm.vynce.utils.PayloadLoader;
import okhttp3.Response;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

public class CommandInjectionTest extends BaseVulnerabilityTest {

    private List<String> commandInjectionPayloads;
    private List<String> commandOutputIndicators;

    @Override
    public TestType getTestType() {
        return TestType.COMMAND_INJECTION;
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
        commandInjectionPayloads = PayloadLoader.loadPayloads("command-injection.json", "payloads");
        commandOutputIndicators = PayloadLoader.loadPayloads("command-injection.json", "output_indicators");
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
                testCommandInjection(context, testUrl, paramName);
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

    private void testCommandInjection(ScanContext context, String url, String paramName) {
        for (String payload : commandInjectionPayloads) {
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
        int matchCount = 0;
        for (String indicator : commandOutputIndicators) {
            try {
                if (Pattern.compile(indicator).matcher(body).find()) {
                    matchCount++;
                    ConsoleUI.debug("Command output indicator matched: " + indicator);

                    if (matchCount >= 2) {
                        return true;
                    }
                }
            } catch (Exception e) {
                if (body.contains(indicator)) {
                    matchCount++;
                    ConsoleUI.debug("Command output indicator matched (literal): " + indicator);

                    if (matchCount >= 2) {
                        return true;
                    }
                }
            }
        }
        return false;
    }
}
