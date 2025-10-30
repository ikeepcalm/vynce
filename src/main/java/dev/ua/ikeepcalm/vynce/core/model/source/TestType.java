package dev.ua.ikeepcalm.vynce.core.model.source;

import lombok.Getter;

@Getter
public enum TestType {
    SQL("SQL Injection"),
    XSS("Cross-Site Scripting"),
    CSRF("Cross-Site Request Forgery"),
    SSRF("Server-Side Request Forgery"),
    XXE("XML External Entity"),
    PATH_TRAVERSAL("Path Traversal"),
    COMMAND_INJECTION("Command Injection"),
    LDAP("LDAP Injection"),
    XPATH("XPath Injection"),
    HEADERS("Security Headers"),
    CORS("CORS Misconfiguration"),
    OPEN_REDIRECT("Open Redirect");

    private final String displayName;

    TestType(String displayName) {
        this.displayName = displayName;
    }

}