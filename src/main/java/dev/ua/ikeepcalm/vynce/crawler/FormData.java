package dev.ua.ikeepcalm.vynce.crawler;

import java.util.Map;

public record FormData(String action, String method, Map<String, String> parameters) {
}
