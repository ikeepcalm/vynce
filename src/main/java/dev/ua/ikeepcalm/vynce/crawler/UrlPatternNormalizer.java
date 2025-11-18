package dev.ua.ikeepcalm.vynce.crawler;

import java.net.URL;
import java.util.regex.Pattern;


public class UrlPatternNormalizer {

    private static final Pattern UUID_PATTERN = Pattern.compile(
            "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
    );
    private static final Pattern NUMERIC_ID_PATTERN = Pattern.compile("^\\d+$");
    private static final Pattern HEX_PATTERN = Pattern.compile("^[0-9a-fA-F]{8,}$");
    private static final Pattern HASH_PATTERN = Pattern.compile("^[0-9a-fA-F]{32,}$");
    private static final Pattern EMAIL_PATTERN = Pattern.compile("^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$");


    public static String normalize(String url) {
        try {
            URL urlObj = new URL(url);
            String path = urlObj.getPath();
            String query = urlObj.getQuery();

            String normalizedPath = normalizePath(path);

            String normalizedQuery = normalizeQuery(query);

            StringBuilder result = new StringBuilder();
            result.append(urlObj.getProtocol()).append("://");
            result.append(urlObj.getHost());
            if (urlObj.getPort() != -1 && urlObj.getPort() != urlObj.getDefaultPort()) {
                result.append(":").append(urlObj.getPort());
            }
            result.append(normalizedPath);
            if (normalizedQuery != null) {
                result.append("?").append(normalizedQuery);
            }

            return result.toString();
        } catch (Exception e) {
            return url;
        }
    }

    private static String normalizePath(String path) {
        if (path == null || path.isEmpty() || path.equals("/")) {
            return path;
        }

        String[] segments = path.split("/");
        StringBuilder normalizedPath = new StringBuilder();

        for (String segment : segments) {
            if (segment.isEmpty()) {
                continue;
            }

            normalizedPath.append("/");

            if (UUID_PATTERN.matcher(segment).matches()) {
                normalizedPath.append("{uuid}");
            } else if (HASH_PATTERN.matcher(segment).matches()) {
                normalizedPath.append("{hash}");
            } else if (HEX_PATTERN.matcher(segment).matches()) {
                normalizedPath.append("{hex}");
            } else if (NUMERIC_ID_PATTERN.matcher(segment).matches()) {
                normalizedPath.append("{id}");
            } else if (EMAIL_PATTERN.matcher(segment).matches()) {
                normalizedPath.append("{email}");
            } else if (isLikelyDynamicSegment(segment)) {
                normalizedPath.append("{param}");
            } else {
                normalizedPath.append(segment);
            }
        }

        return normalizedPath.isEmpty() ? "/" : normalizedPath.toString();
    }


    private static boolean isLikelyDynamicSegment(String segment) {
        if (isCommonStaticSegment(segment)) {
            return false;
        }

        boolean hasLetters = segment.matches(".*[a-zA-Z].*");
        boolean hasNumbers = segment.matches(".*\\d.*");
        boolean hasSpecialChars = segment.matches(".*[_\\-.].*");

        if ((hasLetters && hasNumbers) || hasSpecialChars) {
            return !segment.matches(".*\\.(html?|php|jsp|asp|css|js|json|xml)$");
        }

        return segment.length() > 20;
    }

    private static boolean isCommonStaticSegment(String segment) {
        String lower = segment.toLowerCase();

        return lower.equals("api") || lower.equals("v1") || lower.equals("v2") || lower.equals("v3") ||
               lower.equals("admin") || lower.equals("user") || lower.equals("users") ||
               lower.equals("login") || lower.equals("logout") || lower.equals("register") ||
               lower.equals("profile") || lower.equals("settings") || lower.equals("dashboard") ||
               lower.equals("search") || lower.equals("view") || lower.equals("edit") ||
               lower.equals("delete") || lower.equals("create") || lower.equals("update") ||
               lower.equals("list") || lower.equals("index") || lower.equals("home") ||
               lower.equals("about") || lower.equals("contact") || lower.equals("help") ||
               lower.equals("static") || lower.equals("assets") || lower.equals("images") ||
               lower.equals("css") || lower.equals("js") || lower.equals("img") ||
               lower.equals("public") || lower.equals("private") || lower.equals("report") ||
               lower.equals("com") || lower.equals("org") || lower.equals("net") ||
               lower.equals("page") || lower.equals("article") || lower.equals("post") ||
               lower.equals("category") || lower.equals("tag") || lower.equals("file") ||
               lower.equals("download") || lower.equals("upload");
    }

    private static String normalizeQuery(String query) {
        if (query == null || query.isEmpty()) {
            return null;
        }

        String[] params = query.split("&");
        java.util.Arrays.sort(params);

        StringBuilder normalized = new StringBuilder();
        for (int i = 0; i < params.length; i++) {
            if (i > 0) {
                normalized.append("&");
            }

            String[] parts = params[i].split("=", 2);
            normalized.append(parts[0]).append("={value}");
        }

        return normalized.toString();
    }

    public static String getPatternKey(String url) {
        try {
            URL urlObj = new URL(url);
            String path = normalizePath(urlObj.getPath());
            String query = normalizeQuery(urlObj.getQuery());

            if (query != null) {
                return path + "?" + query;
            }
            return path;
        } catch (Exception e) {
            return url;
        }
    }
}
