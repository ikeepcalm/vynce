package dev.ua.ikeepcalm.vynce.tests;

import dev.ua.ikeepcalm.vynce.core.model.source.TestType;
import dev.ua.ikeepcalm.vynce.tests.impl.*;
import dev.ua.ikeepcalm.vynce.ui.ConsoleUI;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class TestFactory {

    private static final Map<TestType, Class<? extends VulnerabilityTest>> builtInRegistry = new HashMap<>();
    private static final Map<TestType, VulnerabilityTest> pluginRegistry = new HashMap<>();
    private static boolean pluginsLoaded = false;

    static {
        builtInRegistry.put(TestType.SQL, SqlInjectionTest.class);
        builtInRegistry.put(TestType.XSS, XssTest.class);
        builtInRegistry.put(TestType.HEADERS, SecurityHeadersTest.class);
        builtInRegistry.put(TestType.CSRF, CsrfTest.class);
        builtInRegistry.put(TestType.SSRF, SsrfTest.class);
        builtInRegistry.put(TestType.XXE, XxeTest.class);
        builtInRegistry.put(TestType.PATH_TRAVERSAL, PathTraversalTest.class);
        builtInRegistry.put(TestType.COMMAND_INJECTION, CommandInjectionTest.class);
        builtInRegistry.put(TestType.LDAP, LdapInjectionTest.class);
        builtInRegistry.put(TestType.CORS, CorsTest.class);
        builtInRegistry.put(TestType.OPEN_REDIRECT, OpenRedirectTest.class);
    }


    private static synchronized void loadPlugins() {
        if (pluginsLoaded) {
            return;
        }

        ConsoleUI.debug("Loading vulnerability test plugins from plugins/ directory...");

        List<VulnerabilityTest> plugins = PluginLoader.loadPlugins();

        for (VulnerabilityTest test : plugins) {
            TestType testType = test.getTestType();
            pluginRegistry.put(testType, test);
            ConsoleUI.debug("Registered plugin: " + test.getClass().getName() + " for test type: " + testType);
        }

        pluginsLoaded = true;
    }


    public static VulnerabilityTest createTest(TestType testType) {
        if (!pluginsLoaded) {
            loadPlugins();
        }

        if (pluginRegistry.containsKey(testType)) {
            ConsoleUI.debug("Using plugin for test type: " + testType);
            return pluginRegistry.get(testType);
        }

        Class<? extends VulnerabilityTest> testClass = builtInRegistry.get(testType);

        if (testClass == null) {
            throw new IllegalArgumentException("Unknown test type: " + testType);
        }

        try {
            return testClass.getDeclaredConstructor().newInstance();
        } catch (Exception e) {
            throw new RuntimeException("Failed to create test instance for " + testType, e);
        }
    }

    public static synchronized void reset() {
        pluginRegistry.clear();
        pluginsLoaded = false;
        PluginLoader.reset();
    }
}
