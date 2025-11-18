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
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

import static org.fusesource.jansi.Ansi.Color.*;
import static org.fusesource.jansi.Ansi.ansi;

@Getter
public class WebCrawler {

    private static final char[] SPINNER_CHARS = {'|', '/', '-', '\\'};
    private static final long UPDATE_INTERVAL_MS = 200;

    private final String baseUrl;
    private final VynceHttpClient httpClient;
    private final int maxDepth;
    private final Set<String> visitedUrls;
    private final Set<String> visitedPatterns;
    private final Set<String> discoveredUrls;
    private final List<FormData> discoveredForms;
    private final Map<String, List<String>> urlParameters;

    private int spinnerIndex = 0;
    private long lastUpdateTime = 0;
    private int skippedStaticResources = 0;

    public WebCrawler(String baseUrl, VynceHttpClient httpClient, int maxDepth) {
        this.baseUrl = normalizeUrl(baseUrl);
        this.httpClient = httpClient;
        this.maxDepth = maxDepth;
        this.visitedUrls = ConcurrentHashMap.newKeySet();
        this.visitedPatterns = ConcurrentHashMap.newKeySet();
        this.discoveredUrls = ConcurrentHashMap.newKeySet();
        this.discoveredForms = Collections.synchronizedList(new ArrayList<>());
        this.urlParameters = new ConcurrentHashMap<>();
    }

    public static boolean isStaticResource(String url, boolean checkPaths) {
        try {

            String path = java.net.URLDecoder.decode(url, StandardCharsets.UTF_8).toLowerCase();
            int queryIndex = path.indexOf('?');
            if (queryIndex > 0) {
                path = path.substring(0, queryIndex);
            }

            path = path.trim().replaceAll("[\\s\\p{Cntrl}]+$", "");

            if (checkPaths) {
                String[] staticPaths = {
                        "/wp-content/uploads/",     // WordPress uploads
                        "/wp-content/themes/",      // WordPress themes
                        "/wp-includes/",            // WordPress core files
                        "/uploads/",                // Generic uploads
                        "/static/",                 // Static assets
                        "/assets/",                 // Asset files
                        "/media/",                  // Media files
                        "/css/",                    // Stylesheets
                        "/js/",                     // JavaScript
                        "/fonts/",                  // Font files
                        "/icons/",                  // Icon files
                        "/thumbs/",                 // Thumbnails
                        "/thumbnails/",             // Thumbnails
                        "/temp/",                   // Temporary files
                        "/tmp/",                    // Temporary files
                        "/cache/",                  // Cache files
                        "/_next/static/",           // Next.js static
                        "/dist/",                   // Distribution files
                        "/build/"                   // Build artifacts
                };

                for (String staticPath : staticPaths) {
                    if (path.contains(staticPath)) {
                        return true;
                    }
                }
            }

            String[] staticExtensions = {
                    // Documents
                    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".odt", ".ods", ".odp",
                    ".txt", ".rtf", ".csv",

                    // Images
                    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".svg", ".ico", ".webp", ".tiff", ".tif",

                    // Media
                    ".mp3", ".mp4", ".avi", ".mov", ".wmv", ".flv", ".webm", ".m4v", ".mkv",
                    ".wav", ".ogg", ".m4a", ".aac",

                    // Archives
                    ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz", ".iso",

                    // Code/Assets (usually static)
                    ".css", ".js", ".woff", ".woff2", ".ttf", ".eot", ".otf",

                    // Executables
                    ".exe", ".dll", ".so", ".dylib", ".app", ".dmg", ".pkg", ".deb", ".rpm",

                    // Data formats
                    ".json", ".xml", ".yaml", ".yml", ".toml"
            };

            for (String ext : staticExtensions) {
                if (path.endsWith(ext)) {
                    return true;
                }
            }

            return false;
        } catch (Exception e) {
            return false;
        }
    }

    public void crawl() {
        ConsoleUI.debug("Starting web crawl from: " + baseUrl);

        if (!ConsoleUI.isVerbose()) {
            updateCrawlStatus();
        }

        crawlRecursive(baseUrl, 0);

        if (!ConsoleUI.isVerbose()) {
            clearCrawlStatus();
        }

        int totalUrls = discoveredUrls.size();
        int uniquePatterns = visitedPatterns.size();
        int urlsSaved = totalUrls - uniquePatterns;

        StringBuilder summary = new StringBuilder();
        summary.append("Crawl complete. Found ").append(totalUrls).append(" URLs");

        if (uniquePatterns > 0 && urlsSaved > 0) {
            summary.append(" (").append(uniquePatterns)
                    .append(" unique patterns, skipped ").append(urlsSaved).append(" duplicates)");
        }

        if (skippedStaticResources > 0) {
            summary.append(", skipped ").append(skippedStaticResources).append(" static resources");
        }

        summary.append(", ").append(discoveredForms.size()).append(" forms");

        ConsoleUI.debug(summary.toString());
    }

    private void updateCrawlStatus() {
        long currentTime = System.currentTimeMillis();
        if (currentTime - lastUpdateTime < UPDATE_INTERVAL_MS) {
            return;
        }

        lastUpdateTime = currentTime;
        spinnerIndex = (spinnerIndex + 1) % SPINNER_CHARS.length;

        String status = ansi()
                .fg(CYAN).a("[" + SPINNER_CHARS[spinnerIndex] + "]").reset()
                .a(" Crawling... ")
                .fg(YELLOW).a(discoveredUrls.size()).reset()
                .a(" URLs discovered, ")
                .fg(GREEN).a(discoveredForms.size()).reset()
                .a(" forms found")
                .toString();

        System.out.print("\r" + status);
        System.out.flush();
    }

    private void clearCrawlStatus() {
        System.out.print("\r" + " ".repeat(80) + "\r");
        System.out.flush();
    }

    private void crawlRecursive(String url, int depth) {
        if (depth > maxDepth) {
            return;
        }

        if (!isSameDomain(url)) {
            ConsoleUI.debug("Skipping external URL: " + url);
            return;
        }

        if (isStaticResource(url, true)) {
            skippedStaticResources++;
            ConsoleUI.debug("Skipping static resource: " + url);
            return;
        }

        String pattern = UrlPatternNormalizer.getPatternKey(url);

        boolean isNewUrl = discoveredUrls.add(url);

        if (visitedUrls.contains(url)) {
            return;
        }

        if (visitedPatterns.contains(pattern)) {
            ConsoleUI.debug("Skipping similar pattern (already crawled): " + url + " -> " + pattern);
            return;
        }

        visitedUrls.add(url);
        visitedPatterns.add(pattern);

        try {
            ConsoleUI.debug("Crawling: " + url + " (depth: " + depth + ")");

            try (Response response = httpClient.get(url, Collections.emptyMap())) {
                if (response.code() != 200) {
                    ConsoleUI.debug("Non-200 response for " + url + ": " + response.code());
                    return;
                }

                String contentType = response.header("Content-Type", "");
                if (contentType != null && !contentType.contains("text/html")) {
                    ConsoleUI.debug("Skipping non-HTML content: " + contentType);
                    return;
                }

                String body = response.body() != null ? response.body().string() : "";
                Document doc = Jsoup.parse(body, url);

                extractLinks(doc, depth);

                extractForms(doc, url);

                extractUrlParameters(url);

                if (!ConsoleUI.isVerbose()) {
                    updateCrawlStatus();
                }
            }

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

                if (isStaticResource(cleanUrl, true)) {
                    skippedStaticResources++;
                    ConsoleUI.debug("Skipping static resource in links: " + cleanUrl);
                    continue;
                }

                discoveredUrls.add(cleanUrl);

                if (!visitedUrls.contains(cleanUrl)) {
                    String pattern = UrlPatternNormalizer.getPatternKey(cleanUrl);
                    if (!visitedPatterns.contains(pattern)) {
                        crawlRecursive(cleanUrl, currentDepth + 1);
                    } else {
                        ConsoleUI.debug("Skipping similar pattern in links: " + cleanUrl + " -> " + pattern);
                    }
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


    public List<String> getUniquePatternUrls() {
        Map<String, String> patternToRepresentative = new HashMap<>();

        for (String url : discoveredUrls) {
            String pattern = UrlPatternNormalizer.getPatternKey(url);
            patternToRepresentative.putIfAbsent(pattern, url);
        }

        return new ArrayList<>(patternToRepresentative.values());
    }

    public List<String> getUniquePatternUrlsWithParams() {
        Map<String, String> patternToRepresentative = new HashMap<>();

        for (String url : getUrlsWithParams()) {
            String pattern = UrlPatternNormalizer.getPatternKey(url);
            patternToRepresentative.putIfAbsent(pattern, url);
        }

        return new ArrayList<>(patternToRepresentative.values());
    }
}
