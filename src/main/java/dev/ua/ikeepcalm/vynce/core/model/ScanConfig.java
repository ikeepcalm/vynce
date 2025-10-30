package dev.ua.ikeepcalm.vynce.core.model;

import lombok.Builder;
import lombok.Getter;

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
}
