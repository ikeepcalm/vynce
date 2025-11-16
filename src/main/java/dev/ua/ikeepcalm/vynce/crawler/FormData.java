package dev.ua.ikeepcalm.vynce.crawler;

import lombok.AllArgsConstructor;
import lombok.Getter;

import java.util.Map;

@Getter
@AllArgsConstructor
public class FormData {
    private final String action;
    private final String method;
    private final Map<String, String> parameters;
}
