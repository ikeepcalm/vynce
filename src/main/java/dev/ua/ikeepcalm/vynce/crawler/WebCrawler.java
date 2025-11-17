package dev.ua.ikeepcalm.vynce.crawler;

import dev.ua.ikeepcalm.vynce.http.VynceHttpClient;
import dev.ua.ikeepcalm.vynce.ui.ConsoleUI;
import lombok.Getter;
import okhttp3.Response;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

import java.io.IOException;
import java.net.URL;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

@Getter
public class WebCrawler {

    private final String baseUrl;
    private final VynceHttpClient httpClient;
    private final int maxDepth;
    private final Set<String> visitedUrls;
    private final Set<String> discoveredUrls;
    private final List<FormData> discoveredForms;
    private final Map<String, List<String>> urlParameters;

    public WebCrawler(String baseUrl, VynceHttpClient httpClient, int maxDepth) {
        this.baseUrl = normalizeUrl(baseUrl);
        this.httpClient = httpClient;
        this.maxDepth = maxDepth;
        this.visitedUrls = ConcurrentHashMap.newKeySet();
        this.discoveredUrls = ConcurrentHashMap.newKeySet();
        this.discoveredForms = Collections.synchronizedList(new ArrayList<>());
        this.urlParameters = new ConcurrentHashMap<>();
    }

    public void crawl() {
        ConsoleUI.debug("Starting web crawl from: " + baseUrl);
        crawlRecursive(baseUrl, 0);
        ConsoleUI.debug("Crawl complete. Found " + discoveredUrls.size() + " URLs and " + discoveredForms.size() + " forms");
    }

    private void crawlRecursive(String url, int depth) {
        if (depth > maxDepth || visitedUrls.contains(url)) {
            return;
        }

        if (!isSameDomain(url)) {
            ConsoleUI.debug("Skipping external URL: " + url);
            return;
        }

        visitedUrls.add(url);
        discoveredUrls.add(url);

        try {
            ConsoleUI.debug("Crawling: " + url + " (depth: " + depth + ")");
            Response response = httpClient.get(url, Collections.emptyMap());

            if (response.code() != 200) {
                ConsoleUI.debug("Non-200 response for " + url + ": " + response.code());
                return;
            }

            String contentType = response.header("Content-Type", "");
            if (!contentType.contains("text/html")) {
                ConsoleUI.debug("Skipping non-HTML content: " + contentType);
                return;
            }

            String body = response.body() != null ? response.body().string() : "";
            Document doc = Jsoup.parse(body, url);

            // Extract links
            extractLinks(doc, depth);

            // Extract forms
            extractForms(doc, url);

            // Extract URL parameters
            extractUrlParameters(url);

        } catch (IOException e) {
            ConsoleUI.debug("Error crawling " + url + ": " + e.getMessage());
        }
    }

    private void extractLinks(Document doc, int currentDepth) {
        Elements links = doc.select("a[href]");

        for (Element link : links) {
            String href = link.absUrl("href");
            if (!href.isEmpty() && isSameDomain(href)) {
                String cleanUrl = removeFragment(href);
                if (!visitedUrls.contains(cleanUrl)) {
                    crawlRecursive(cleanUrl, currentDepth + 1);
                }
            }
        }
    }

    private void extractForms(Document doc, String pageUrl) {
        Elements forms = doc.select("form");

        for (Element form : forms) {
            String action = form.absUrl("action");
            if (action.isEmpty()) {
                action = pageUrl;
            }

            String method = form.attr("method").toUpperCase();
            if (method.isEmpty()) {
                method = "GET";
            }

            Map<String, String> inputs = new HashMap<>();
            Elements inputElements = form.select("input, select, textarea");

            for (Element input : inputElements) {
                String name = input.attr("name");
                String type = input.attr("type");
                String value = input.attr("value");

                if (!name.isEmpty() && !type.equals("submit") && !type.equals("button")) {
                    inputs.put(name, value.isEmpty() ? "test" : value);
                }
            }

            if (!inputs.isEmpty()) {
                FormData formData = new FormData(action, method, inputs);
                discoveredForms.add(formData);
                ConsoleUI.debug("Found form: " + method + " " + action +
                        " with " + inputs.size() + " parameters");
            }
        }
    }

    private void extractUrlParameters(String url) {
        try {
            URL urlObj = new URL(url);
            String query = urlObj.getQuery();

            if (query != null && !query.isEmpty()) {
                String baseWithoutParams = url.split("\\?")[0];
                List<String> params = new ArrayList<>();

                for (String param : query.split("&")) {
                    String[] parts = param.split("=");
                    if (parts.length > 0) {
                        params.add(parts[0]);
                    }
                }

                if (!params.isEmpty()) {
                    urlParameters.put(baseWithoutParams, params);
                    ConsoleUI.debug("Found URL parameters: " + params + " in " + baseWithoutParams);
                }
            }
        } catch (Exception e) {
            ConsoleUI.debug("Error extracting parameters from " + url + ": " + e.getMessage());
        }
    }

    private boolean isSameDomain(String url) {
        try {
            URL base = new URL(baseUrl);
            URL target = new URL(url);
            return base.getHost().equals(target.getHost());
        } catch (Exception e) {
            return false;
        }
    }

    private String removeFragment(String url) {
        int fragmentIndex = url.indexOf('#');
        return fragmentIndex > 0 ? url.substring(0, fragmentIndex) : url;
    }

    private String normalizeUrl(String url) {
        if (!url.endsWith("/")) {
            return url;
        }
        return url;
    }

    public List<String> getUrlsWithParams() {
        return new ArrayList<>(urlParameters.keySet());
    }

    public Map<String, String> getParamsForUrl(String url) {
        List<String> params = urlParameters.get(url);
        if (params == null) {
            return Collections.emptyMap();
        }

        Map<String, String> result = new HashMap<>();
        for (String param : params) {
            result.put(param, "test");
        }
        return result;
    }

    public List<String> getAllUrls() {
        return new ArrayList<>(discoveredUrls);
    }
}
