package dev.ua.ikeepcalm.vynce.tests;

import dev.ua.ikeepcalm.vynce.ui.ConsoleUI;

import java.io.File;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;


public class PluginLoader {

    private static final String PLUGINS_DIR = "plugins";
    private static final List<VulnerabilityTest> loadedPlugins = new ArrayList<>();
    private static boolean loaded = false;

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

    private static List<VulnerabilityTest> loadPluginFromJar(File jarFile) throws Exception {
        List<VulnerabilityTest> tests = new ArrayList<>();

        URL jarUrl = jarFile.toURI().toURL();
        URLClassLoader classLoader = new URLClassLoader(
                new URL[]{jarUrl},
                PluginLoader.class.getClassLoader()
        );

        try (JarFile jar = new JarFile(jarFile)) {
            Enumeration<JarEntry> entries = jar.entries();

            while (entries.hasMoreElements()) {
                JarEntry entry = entries.nextElement();
                String name = entry.getName();

                if (name.endsWith(".class") && !name.contains("$")) {
                    String className = name.replace('/', '.').replace(".class", "");

                    try {
                        Class<?> clazz = classLoader.loadClass(className);

                        if (VulnerabilityTest.class.isAssignableFrom(clazz) &&
                            !clazz.isInterface() &&
                            !java.lang.reflect.Modifier.isAbstract(clazz.getModifiers())) {

                            VulnerabilityTest test = (VulnerabilityTest) clazz.getDeclaredConstructor().newInstance();
                            tests.add(test);

                            ConsoleUI.debug("  Found test: " + clazz.getSimpleName() +
                                            " (type: " + test.getTestType() + ")");
                        }
                    } catch (ClassNotFoundException ignored) {
                    } catch (NoClassDefFoundError e) {
                        ConsoleUI.debug("  Skipped " + className + " (missing dependencies)");
                    } catch (Exception e) {
                        ConsoleUI.debug("  Failed to instantiate " + className + ": " + e.getMessage());
                    }
                }
            }
        }

        return tests;
    }

    private static Path getPluginsDirectory() {
        try {
            String jarPath = PluginLoader.class.getProtectionDomain()
                    .getCodeSource()
                    .getLocation()
                    .toURI()
                    .getPath();

            File jarFile = new File(jarPath);

            if (jarFile.isFile()) {
                return jarFile.getParentFile().toPath().resolve(PLUGINS_DIR);
            }
        } catch (Exception e) {
        }

        return Paths.get(PLUGINS_DIR);
    }

    public static synchronized void reset() {
        loadedPlugins.clear();
        loaded = false;
    }
}
