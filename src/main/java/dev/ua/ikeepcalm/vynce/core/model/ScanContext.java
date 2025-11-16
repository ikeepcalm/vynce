package dev.ua.ikeepcalm.vynce.core.model;

import dev.ua.ikeepcalm.vynce.crawler.WebCrawler;
import dev.ua.ikeepcalm.vynce.http.VynceHttpClient;
import lombok.Getter;

@Getter
public class ScanContext {

    private final String targetUrl;
    private final VynceHttpClient httpClient;
    private final ScanConfig config;
    private final WebCrawler crawler;

    public ScanContext(String targetUrl, ScanConfig config) {
        this.targetUrl = targetUrl;
        this.config = config;
        this.httpClient = new VynceHttpClient(config);
        this.crawler = new WebCrawler(targetUrl, httpClient, config.getCrawlDepth());
    }

    public void initializeCrawler() {
        crawler.crawl();
    }

    public void close() {
        httpClient.close();
    }
}
