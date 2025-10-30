package dev.ua.ikeepcalm.vynce.core.model;

import dev.ua.ikeepcalm.vynce.http.VynceHttpClient;
import lombok.Getter;

@Getter
public class ScanContext {

    private final String targetUrl;
    private final VynceHttpClient httpClient;
    private final ScanConfig config;

    public ScanContext(String targetUrl, ScanConfig config) {
        this.targetUrl = targetUrl;
        this.config = config;
        this.httpClient = new VynceHttpClient(config);
    }

    public void close() {
        httpClient.close();
    }
}
