package dev.ua.ikeepcalm.vynce.http;

import lombok.Getter;
import okhttp3.Interceptor;
import okhttp3.Response;
import org.jetbrains.annotations.NotNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;

public class RateLimitInterceptor implements Interceptor {

    private static final Logger logger = LoggerFactory.getLogger(RateLimitInterceptor.class);
    private final int delayMs;

    @Getter
    private int rpsMetric;

    public RateLimitInterceptor(int delayMs) {
        this.delayMs = delayMs;
    }

    @NotNull
    @Override
    public Response intercept(@NotNull Chain chain) throws IOException {
        rpsMetric++;

        if (delayMs > 0) {
            try {
                Thread.sleep(delayMs);
            } catch (InterruptedException e) {
                logger.warn("Rate limiting interrupted", e);
                Thread.currentThread().interrupt();
            }
        }

        return chain.proceed(chain.request());
    }

}
