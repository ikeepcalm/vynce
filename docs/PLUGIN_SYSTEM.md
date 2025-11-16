# Vynce Plugin System Guide

## Overview

Vynce Scanner features a dynamic plugin system that allows you to extend its functionality by simply dropping JAR files into a `plugins/` folder. No classpath modification or configuration files needed.

## How It Works

### Directory Structure

```
your-project/
├── vynce.jar              # Main scanner JAR
└── plugins/               # Plugin directory
    ├── graphql-tests.jar  # Custom GraphQL tests
    ├── api-tests.jar      # Custom API tests
    └── custom-checks.jar  # Your custom vulnerability checks
```

### Loading Process

1. **Automatic Discovery**: When Vynce starts, it looks for a `plugins/` directory next to the JAR file
2. **JAR Scanning**: All `.jar` files in the plugins directory are loaded
3. **Class Discovery**: Each JAR is scanned for classes implementing `VulnerabilityTest`
4. **Registration**: Found tests are registered and made available for scanning
5. **Priority**: Plugin tests take priority over built-in tests of the same type

## Creating a Plugin

### Step 1: Create Your Test Class

```java
package com.example.myplugin;

import dev.ua.ikeepcalm.vynce.core.model.ScanContext;
import dev.ua.ikeepcalm.vynce.core.model.Vulnerability;
import dev.ua.ikeepcalm.vynce.core.model.source.Severity;
import dev.ua.ikeepcalm.vynce.core.model.source.TestType;
import dev.ua.ikeepcalm.vynce.tests.BaseVulnerabilityTest;
import okhttp3.Response;

public class CustomSecurityTest extends BaseVulnerabilityTest {

    @Override
    public TestType getTestType() {
        // You can override built-in tests or create custom ones
        return TestType.SSRF;
    }

    @Override
    protected void runTests(ScanContext context) throws Exception {
        // Access the web crawler
        for (String url : context.getCrawler().getAllUrls()) {
            testUrl(context, url);
        }
    }

    private void testUrl(ScanContext context, String url) {
        try {
            Response response = context.getHttpClient().get(url);
            String body = response.body() != null ? response.body().string() : "";

            // Your detection logic
            if (body.contains("vulnerable-pattern")) {
                addVulnerability(new Vulnerability(
                    Severity.HIGH,
                    "Custom Vulnerability Found",
                    "Detailed description of the issue",
                    url,
                    "attack payload used"
                ));
            }
        } catch (Exception e) {
            // Handle errors
        }
    }
}
```

### Step 2: Create build.gradle.kts

```kotlin
plugins {
    id("java")
}

group = "com.example"
version = "1.0.0"

repositories {
    mavenCentral()
}

dependencies {
    // Add Vynce as a dependency
    compileOnly(files("/path/to/vynce-1.0.0-all.jar"))

    // Or if using a local Maven repository
    // compileOnly("dev.ua.ikeepcalm.vynce:vynce:1.0.0")

    implementation("com.squareup.okhttp3:okhttp:4.12.0")
}

tasks.jar {
    archiveFileName.set("${project.name}-${project.version}.jar")
}
```

### Step 3: Build Your Plugin

```bash
./gradlew build
```

This creates: `build/libs/my-plugin-1.0.0.jar`

### Step 4: Deploy Your Plugin

```bash
# Copy to plugins directory
cp build/libs/my-plugin-1.0.0.jar /path/to/vynce/plugins/
```

### Step 5: Run Vynce

```bash
cd /path/to/vynce
java -jar vynce-1.0.0-all.jar scan https://target.com
```

## Example Output

```
Loading plugins from: /home/user/vynce/plugins
Loading plugin JAR: my-plugin-1.0.0.jar
  Found test: CustomSecurityTest (type: SSRF)
Loaded 1 test(s) from my-plugin-1.0.0.jar
Total plugins loaded: 1 test(s) from 1 JAR(s)

Starting vulnerability scan...
```

## Advanced Features

### Accessing the Crawler

The crawler discovers URLs, forms, and parameters:

```java
// Get all discovered URLs
List<String> urls = context.getCrawler().getAllUrls();

// Get URLs with parameters
List<String> paramUrls = context.getCrawler().getUrlsWithParams();

// Get discovered forms
List<FormData> forms = context.getCrawler().getDiscoveredForms();

// Get parameters for a specific URL
Map<String, String> params = context.getCrawler().getParamsForUrl(url);
```

### Using the HTTP Client

```java
// Simple GET request
Response response = context.getHttpClient().get(url);

// GET with headers
Map<String, String> headers = Map.of("Authorization", "Bearer token");
Response response = context.getHttpClient().get(url, headers);

// POST request
Map<String, String> params = Map.of("username", "test", "password", "test");
Response response = context.getHttpClient().post(url, params);

// Custom request
Request request = new Request.Builder()
    .url(url)
    .post(RequestBody.create(jsonData, MediaType.parse("application/json")))
    .build();
Response response = context.getHttpClient().executeRequest(request);
```

### Logging and Debugging

```java
import dev.ua.ikeepcalm.vynce.ui.ConsoleUI;

// Info messages (always shown)
ConsoleUI.info("Starting custom test");

// Success messages
ConsoleUI.success("Test completed successfully");

// Warnings
ConsoleUI.warning("Potential issue detected");

// Errors
ConsoleUI.error("Test failed: " + e.getMessage());

// Debug messages (only shown with --verbose)
ConsoleUI.debug("Processing URL: " + url);
```

### Helper Methods (from BaseVulnerabilityTest)

```java
// URL encoding
String encoded = encodeUrl("test&param=value");

// Extract parameters from URL
Map<String, String> params = extractParams("http://example.com?id=1&name=test");

// Inject payload into parameter
String maliciousUrl = injectPayload("http://example.com?id=1", "id", "' OR 1=1--");
```

## Overriding Built-in Tests

You can replace any built-in test by creating a plugin with the same `TestType`:

```java
@Override
public TestType getTestType() {
    return TestType.SQL;  // Override the built-in SQL injection test
}
```

When Vynce loads, your plugin version will be used instead of the built-in one.

## Plugin Distribution

### As a Single JAR

Simply distribute your JAR file:

```
my-awesome-tests-1.0.0.jar
```

Users install it with:

```bash
cp my-awesome-tests-1.0.0.jar /path/to/vynce/plugins/
```

### With Dependencies

If your plugin has dependencies, create a fat JAR:

```kotlin
// build.gradle.kts
plugins {
    id("com.github.johnrengelman.shadow") version "8.1.1"
}

tasks.shadowJar {
    archiveFileName.set("${project.name}-${project.version}-all.jar")
}
```

Build with:

```bash
./gradlew shadowJar
```

## Example Plugins Included

The `vynce-plugins` subproject includes two example plugins:

### 1. GraphQLTest

Tests for GraphQL-specific vulnerabilities:
- Introspection query detection
- Query batching abuse
- Schema exposure

### 2. JWTTest

JWT security validation:
- Detects 'none' algorithm vulnerabilities
- Identifies weak HMAC algorithms
- Checks for missing expiration claims
- Finds tokens exposed in responses

Build the examples:

```bash
./gradlew :vynce-plugins:build
cp vynce-plugins/build/libs/vynce-plugins-1.0.0.jar plugins/
```

## Troubleshooting

### Plugin Not Loading

1. **Check JAR location**: Ensure JAR is in `plugins/` directory
2. **Verify JAR structure**: Open JAR and check for `.class` files
3. **Run with verbose**: Use `--verbose` flag to see loading details
4. **Check dependencies**: Ensure all dependencies are included

### ClassNotFoundException

Your plugin might have missing dependencies. Create a fat JAR with all dependencies included.

### Plugin Conflicts

If multiple plugins implement the same `TestType`, the last loaded plugin wins. Check logs to see which plugin is being used.

## Best Practices

1. **Use BaseVulnerabilityTest**: Provides helpful utilities
2. **Handle Exceptions**: Wrap risky code in try-catch
3. **Use Debug Logging**: Help users troubleshoot issues
4. **Document Your Tests**: Explain what your plugin checks for
5. **Test Thoroughly**: Verify against real and test targets
6. **Version Your Plugins**: Use semantic versioning
7. **Include Dependencies**: Bundle everything users need

## Security Considerations

1. **Validate Inputs**: Don't trust data from scanned sites
2. **Limit Resource Usage**: Be mindful of memory and CPU
3. **Respect Rate Limits**: Don't overwhelm target servers
4. **Follow Ethical Guidelines**: Only scan authorized targets
5. **Review Third-Party Plugins**: Inspect code before deployment

## Plugin API Reference

### Core Interfaces

- `VulnerabilityTest`: Main interface for tests
- `BaseVulnerabilityTest`: Abstract base class with utilities

### Models

- `ScanContext`: Access to target, config, HTTP client, crawler
- `ScanConfig`: Scan configuration (timeout, depth, etc.)
- `Vulnerability`: Vulnerability report model
- `Severity`: CRITICAL, HIGH, MEDIUM, LOW, INFO
- `TestType`: SQL, XSS, CSRF, etc.

### Utilities

- `VynceHttpClient`: HTTP operations
- `WebCrawler`: Site discovery
- `ConsoleUI`: Logging and output
- `PayloadLoader`: Load attack payloads from JSON

## Getting Help

- **Documentation**: See `/docs` folder
- **Examples**: Check `vynce-plugins/` subproject
- **Issues**: Report bugs on GitHub
- **Community**: Join discussions
