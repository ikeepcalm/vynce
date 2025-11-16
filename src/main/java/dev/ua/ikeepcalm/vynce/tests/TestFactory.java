package dev.ua.ikeepcalm.vynce.tests;

import dev.ua.ikeepcalm.vynce.core.model.source.TestType;
import dev.ua.ikeepcalm.vynce.tests.impl.*;
import dev.ua.ikeepcalm.vynce.ui.ConsoleUI;

import java.util.HashMap;
import java.util.Map;
import java.util.ServiceLoader;

public class TestFactory {

    private static final Map<TestType, Class<? extends VulnerabilityTest>> builtInRegistry = new HashMap<>();
    private static final Map<TestType, VulnerabilityTest> pluginRegistry = new HashMap<>();
    private static boolean pluginsLoaded = false;

    static {
        // Register built-in tests
        builtInRegistry.put(TestType.SQL, SqlInjectionTest.class);
        builtInRegistry.put(TestType.XSS, XssTest.class);
        builtInRegistry.put(TestType.HEADERS, SecurityHeadersTest.class);
        builtInRegistry.put(TestType.CSRF, CsrfTest.class);
        builtInRegistry.put(TestType.SSRF, SsrfTest.class);
        builtInRegistry.put(TestType.XXE, XxeTest.class);
        builtInRegistry.put(TestType.PATH_TRAVERSAL, PathTraversalTest.class);
        builtInRegistry.put(TestType.COMMAND_INJECTION, CommandInjectionTest.class);
        builtInRegistry.put(TestType.LDAP, LdapInjectionTest.class);
        builtInRegistry.put(TestType.XPATH, XpathInjectionTest.class);
        builtInRegistry.put(TestType.CORS, CorsTest.class);
        builtInRegistry.put(TestType.OPEN_REDIRECT, OpenRedirectTest.class);
    }

    /**
     * Load plugins using ServiceLoader mechanism.
     * This allows third-party tests to be discovered at runtime.
     */
    private static synchronized void loadPlugins() {
        if (pluginsLoaded) {
            return;
        }

        ConsoleUI.debug("Loading vulnerability test plugins...");

        ServiceLoader<VulnerabilityTest> loader = ServiceLoader.load(VulnerabilityTest.class);
        int pluginCount = 0;

        for (VulnerabilityTest test : loader) {
            TestType testType = test.getTestType();
            pluginRegistry.put(testType, test);
            pluginCount++;
            ConsoleUI.debug("Loaded plugin: " + test.getClass().getName() + " for test type: " + testType);
        }

        if (pluginCount > 0) {
            ConsoleUI.info("Loaded " + pluginCount + " plugin test(s)");
        } else {
            ConsoleUI.debug("No plugins found, using built-in tests only");
        }

        pluginsLoaded = true;
    }

    /**
     * Create a test instance for the given test type.
     * First checks for plugin implementations, then falls back to built-in tests.
     */
    public static VulnerabilityTest createTest(TestType testType) {
        // Load plugins on first access
        if (!pluginsLoaded) {
            loadPlugins();
        }

        // Check if a plugin provides this test
        if (pluginRegistry.containsKey(testType)) {
            ConsoleUI.debug("Using plugin for test type: " + testType);
            return pluginRegistry.get(testType);
        }

        // Fall back to built-in test
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

    /**
     * Reset the plugin loader state. Useful for testing.
     */
    public static synchronized void reset() {
        pluginRegistry.clear();
        pluginsLoaded = false;
    }
}
