package dev.ua.ikeepcalm.vynce.core.model;

import lombok.Builder;
import lombok.Getter;

import java.util.HashMap;
import java.util.Map;

@Getter
@Builder
public class ScanConfig {

    @Builder.Default
    private int timeout = 30;

    @Builder.Default
    private boolean followRedirects = true;

    @Builder.Default
    private String userAgent = "Vynce Scanner/1.0";

    @Builder.Default
    private int requestDelay = 0;

    @Builder.Default
    private int threads = 5;

    @Builder.Default
    private int crawlDepth = 3;

    @Builder.Default
    private int maxRetries = 2;

    @Builder.Default
    private boolean verbose = false;

    private String username;
    private String password;
    private String apiKey;
    private String bearerToken;

    @Builder.Default
    private Map<String, String> customHeaders = new HashMap<>();


    @Override
    public String toString() {
        return "ScanConfig{" +
               "timeout=" + timeout +
               ", followRedirects=" + followRedirects +
               ", userAgent='" + userAgent + '\'' +
               ", requestDelay=" + requestDelay +
               ", threads=" + threads +
               ", crawlDepth=" + crawlDepth +
               ", maxRetries=" + maxRetries +
               ", username='" + (username != null ? "***REDACTED***" : "null") + '\'' +
               ", password='" + (password != null ? "***REDACTED***" : "null") + '\'' +
               ", apiKey='" + (apiKey != null ? "***REDACTED***" : "null") + '\'' +
               ", bearerToken='" + (bearerToken != null ? "***REDACTED***" : "null") + '\'' +
               ", customHeaders=" + redactHeaders() +
               '}';
    }


    private Map<String, String> redactHeaders() {
        if (customHeaders == null || customHeaders.isEmpty()) {
            return customHeaders;
        }

        Map<String, String> redacted = new HashMap<>();
        for (Map.Entry<String, String> entry : customHeaders.entrySet()) {
            String key = entry.getKey().toLowerCase();
            if (key.contains("auth") || key.contains("token") || key.contains("key") ||
                key.contains("secret") || key.contains("password")) {
                redacted.put(entry.getKey(), "***REDACTED***");
            } else {
                redacted.put(entry.getKey(), entry.getValue());
            }
        }
        return redacted;
    }
}
