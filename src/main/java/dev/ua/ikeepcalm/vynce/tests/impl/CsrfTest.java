package dev.ua.ikeepcalm.vynce.tests.impl;
import dev.ua.ikeepcalm.vynce.ui.ConsoleUI;

import dev.ua.ikeepcalm.vynce.core.model.ScanContext;
import dev.ua.ikeepcalm.vynce.core.model.Vulnerability;
import dev.ua.ikeepcalm.vynce.core.model.source.Severity;
import dev.ua.ikeepcalm.vynce.core.model.source.TestType;
import dev.ua.ikeepcalm.vynce.tests.BaseVulnerabilityTest;
import okhttp3.Response;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

public class CsrfTest extends BaseVulnerabilityTest {

    @Override
    public TestType getTestType() {
        return TestType.CSRF;
    }

    @Override
    protected void runTests(ScanContext context) throws Exception {
        try (Response response = context.getHttpClient().get(context.getTargetUrl())) {
            String html = context.getHttpClient().getBodyAsString(response);
            Document doc = Jsoup.parse(html);

            // Check forms for CSRF tokens
            Elements forms = doc.select("form");

            for (Element form : forms) {
                String method = form.attr("method").toUpperCase();

                // Only check POST, PUT, DELETE forms
                if (method.equals("POST") || method.equals("PUT") || method.equals("DELETE") || method.isEmpty()) {
                    if (!hasCsrfToken(form)) {
                        String action = form.attr("action");
                        addVulnerability(createVulnerability(
                                Severity.MEDIUM,
                                "Form without CSRF protection detected. Action: " + (action.isEmpty() ? "(current page)" : action),
                                context.getTargetUrl()
                        ));
                        ConsoleUI.warning("CSRF vulnerability: form without token at " + " " + context.getTargetUrl());
                    }
                }
            }
        }
    }

    private boolean hasCsrfToken(Element form) {
        // Check for common CSRF token field names
        String[] tokenNames = {"csrf", "token", "_token", "csrf_token", "csrftoken", "authenticity_token", "__RequestVerificationToken"};

        for (String tokenName : tokenNames) {
            Element input = form.selectFirst("input[name*=" + tokenName + "]");
            if (input != null && input.attr("type").equals("hidden")) {
                return true;
            }
        }

        return false;
    }
}
