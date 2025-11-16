package dev.ua.ikeepcalm.vynce.http;

import dev.ua.ikeepcalm.vynce.core.model.ScanConfig;
import dev.ua.ikeepcalm.vynce.ui.ConsoleUI;
import okhttp3.*;

import java.io.IOException;
import java.util.Map;
import java.util.concurrent.TimeUnit;

public class VynceHttpClient {
    private final OkHttpClient client;
    private final CookieJar cookieJar;

    public VynceHttpClient(ScanConfig config) {
        this.cookieJar = CookieJar.NO_COOKIES;

        OkHttpClient.Builder builder = new OkHttpClient.Builder()
                .connectTimeout(config.getTimeout(), TimeUnit.SECONDS)
                .readTimeout(config.getTimeout(), TimeUnit.SECONDS)
                .writeTimeout(config.getTimeout(), TimeUnit.SECONDS)
                .followRedirects(config.isFollowRedirects())
                .followSslRedirects(config.isFollowRedirects())
                .cookieJar(cookieJar)
                .addInterceptor(new UserAgentInterceptor(config.getUserAgent()));

        if (config.getRequestDelay() > 0) {
            builder.addInterceptor(new RateLimitInterceptor(config.getRequestDelay()));
        }

        this.client = builder.build();
    }

    public Response get(String url) throws IOException {
        return get(url, Map.of());
    }

    public Response get(String url, Map<String, String> headers) throws IOException {
        Request.Builder builder = new Request.Builder().url(url);
        headers.forEach(builder::addHeader);

        Request request = builder.build();
        ConsoleUI.debug("GET " + url);

        return client.newCall(request).execute();
    }

    public Response post(String url, Map<String, String> params) throws IOException {
        return post(url, params, Map.of());
    }

    public Response post(String url, Map<String, String> params, Map<String, String> headers) throws IOException {
        FormBody.Builder formBuilder = new FormBody.Builder();
        params.forEach(formBuilder::add);

        Request.Builder requestBuilder = new Request.Builder()
                .url(url)
                .post(formBuilder.build());
        headers.forEach(requestBuilder::addHeader);

        Request request = requestBuilder.build();
        ConsoleUI.debug("POST " + url);

        return client.newCall(request).execute();
    }

    public Response postJson(String url, String json) throws IOException {
        return postJson(url, json, Map.of());
    }

    public Response postJson(String url, String json, Map<String, String> headers) throws IOException {
        RequestBody body = RequestBody.create(json, MediaType.get("application/json; charset=utf-8"));

        Request.Builder requestBuilder = new Request.Builder()
                .url(url)
                .post(body);
        headers.forEach(requestBuilder::addHeader);

        Request request = requestBuilder.build();
        ConsoleUI.debug("POST " + url + " (JSON)");

        return client.newCall(request).execute();
    }

    public Response executeRequest(Request request) throws IOException {
        ConsoleUI.debug(request.method() + " " + request.url());
        return client.newCall(request).execute();
    }

    public String getBodyAsString(Response response) throws IOException {
        ResponseBody body = response.body();
        return body != null ? body.string() : "";
    }

    public void close() {
        client.dispatcher().executorService().shutdown();
        client.connectionPool().evictAll();
    }
}
