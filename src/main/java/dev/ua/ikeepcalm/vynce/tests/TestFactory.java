package dev.ua.ikeepcalm.vynce.tests;

import dev.ua.ikeepcalm.vynce.core.model.source.TestType;
import dev.ua.ikeepcalm.vynce.tests.impl.*;

import java.util.HashMap;
import java.util.Map;

public class TestFactory {

    private static final Map<TestType, Class<? extends VulnerabilityTest>> testRegistry = new HashMap<>();

    static {
        testRegistry.put(TestType.SQL, SqlInjectionTest.class);
        testRegistry.put(TestType.XSS, XssTest.class);
        testRegistry.put(TestType.HEADERS, SecurityHeadersTest.class);
        testRegistry.put(TestType.CSRF, CsrfTest.class);
        testRegistry.put(TestType.SSRF, SsrfTest.class);
        testRegistry.put(TestType.XXE, XxeTest.class);
        testRegistry.put(TestType.PATH_TRAVERSAL, PathTraversalTest.class);
        testRegistry.put(TestType.COMMAND_INJECTION, CommandInjectionTest.class);
        testRegistry.put(TestType.LDAP, LdapInjectionTest.class);
        testRegistry.put(TestType.XPATH, XpathInjectionTest.class);
        testRegistry.put(TestType.CORS, CorsTest.class);
        testRegistry.put(TestType.OPEN_REDIRECT, OpenRedirectTest.class);
    }

    public static VulnerabilityTest createTest(TestType testType) {
        Class<? extends VulnerabilityTest> testClass = testRegistry.get(testType);

        if (testClass == null) {
            throw new IllegalArgumentException("Unknown test type: " + testType);
        }

        try {
            return testClass.getDeclaredConstructor().newInstance();
        } catch (Exception e) {
            throw new RuntimeException("Failed to create test instance for " + testType, e);
        }
    }
}
