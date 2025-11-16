package dev.ua.ikeepcalm.vynce.tests;

import dev.ua.ikeepcalm.vynce.ui.ConsoleUI;

import java.io.File;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

/**
 * Dynamically loads vulnerability test plugins from JAR files in a plugins directory.
 * This allows users to drop custom test JARs into a plugins/ folder without modifying the classpath.
 */
public class PluginLoader {

    private static final String PLUGINS_DIR = "plugins";
    private static final List<VulnerabilityTest> loadedPlugins = new ArrayList<>();
    private static boolean loaded = false;

    /**
     * Load all plugin JARs from the plugins/ directory.
     * Expected structure:
     * <pre>
     * vynce.jar
     * plugins/
     *   ├── test1.jar
     *   └── test2.jar
     * </pre>
     */
    public static synchronized List<VulnerabilityTest> loadPlugins() {
        if (loaded) {
            return loadedPlugins;
        }

        Path pluginsPath = getPluginsDirectory();

        if (!Files.exists(pluginsPath)) {
            ConsoleUI.debug("Plugins directory not found: " + pluginsPath.toAbsolutePath());
            ConsoleUI.debug("Create a 'plugins/' folder next to the JAR to add custom tests");
            loaded = true;
            return loadedPlugins;
        }

        ConsoleUI.info("Loading plugins from: " + pluginsPath.toAbsolutePath());

        File pluginsDir = pluginsPath.toFile();
        File[] jarFiles = pluginsDir.listFiles((dir, name) -> name.toLowerCase().endsWith(".jar"));

        if (jarFiles == null || jarFiles.length == 0) {
            ConsoleUI.debug("No JAR files found in plugins directory");
            loaded = true;
            return loadedPlugins;
        }

        int pluginCount = 0;
        for (File jarFile : jarFiles) {
            try {
                ConsoleUI.debug("Loading plugin JAR: " + jarFile.getName());
                List<VulnerabilityTest> tests = loadPluginFromJar(jarFile);
                loadedPlugins.addAll(tests);
                pluginCount += tests.size();

                if (!tests.isEmpty()) {
                    ConsoleUI.success("Loaded " + tests.size() + " test(s) from " + jarFile.getName());
                }
            } catch (Exception e) {
                ConsoleUI.error("Failed to load plugin " + jarFile.getName() + ": " + e.getMessage());
                ConsoleUI.debug("Stack trace: %s", e);
            }
        }

        if (pluginCount > 0) {
            ConsoleUI.success("Total plugins loaded: " + pluginCount + " test(s) from " + jarFiles.length + " JAR(s)");
        }

        loaded = true;
        return loadedPlugins;
    }

    /**
     * Load VulnerabilityTest implementations from a single JAR file.
     */
    private static List<VulnerabilityTest> loadPluginFromJar(File jarFile) throws Exception {
        List<VulnerabilityTest> tests = new ArrayList<>();

        // Create URLClassLoader with the plugin JAR
        URL jarUrl = jarFile.toURI().toURL();
        URLClassLoader classLoader = new URLClassLoader(
            new URL[]{jarUrl},
            PluginLoader.class.getClassLoader()
        );

        // Scan JAR for classes implementing VulnerabilityTest
        try (JarFile jar = new JarFile(jarFile)) {
            Enumeration<JarEntry> entries = jar.entries();

            while (entries.hasMoreElements()) {
                JarEntry entry = entries.nextElement();
                String name = entry.getName();

                // Check if it's a class file
                if (name.endsWith(".class") && !name.contains("$")) {
                    // Convert path to class name
                    String className = name.replace('/', '.').replace(".class", "");

                    try {
                        Class<?> clazz = classLoader.loadClass(className);

                        // Check if it implements VulnerabilityTest
                        if (VulnerabilityTest.class.isAssignableFrom(clazz) &&
                            !clazz.isInterface() &&
                            !java.lang.reflect.Modifier.isAbstract(clazz.getModifiers())) {

                            // Instantiate the test
                            VulnerabilityTest test = (VulnerabilityTest) clazz.getDeclaredConstructor().newInstance();
                            tests.add(test);

                            ConsoleUI.debug("  Found test: " + clazz.getSimpleName() +
                                          " (type: " + test.getTestType() + ")");
                        }
                    } catch (ClassNotFoundException e) {
                        // Skip classes that can't be loaded (might be inner classes or dependencies)
                    } catch (NoClassDefFoundError e) {
                        // Skip classes with missing dependencies
                        ConsoleUI.debug("  Skipped " + className + " (missing dependencies)");
                    } catch (Exception e) {
                        ConsoleUI.debug("  Failed to instantiate " + className + ": " + e.getMessage());
                    }
                }
            }
        }

        return tests;
    }

    /**
     * Get the plugins directory path.
     * Tries to locate it next to the running JAR, or in the current working directory.
     */
    private static Path getPluginsDirectory() {
        // Try to find the directory where the JAR is running from
        try {
            String jarPath = PluginLoader.class.getProtectionDomain()
                .getCodeSource()
                .getLocation()
                .toURI()
                .getPath();

            File jarFile = new File(jarPath);

            if (jarFile.isFile()) {
                // Running from JAR, plugins dir should be next to the JAR
                return jarFile.getParentFile().toPath().resolve(PLUGINS_DIR);
            }
        } catch (Exception e) {
            // Ignore, fall back to working directory
        }

        // Fall back to current working directory
        return Paths.get(PLUGINS_DIR);
    }

    /**
     * Reset the loader state (useful for testing).
     */
    public static synchronized void reset() {
        loadedPlugins.clear();
        loaded = false;
    }
}
