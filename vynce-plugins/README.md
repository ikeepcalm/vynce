# Vynce Custom Test Plugins

This module demonstrates how to create custom vulnerability tests for Vynce Scanner using the ServiceLoader mechanism.

## Overview

Vynce Scanner supports custom vulnerability tests through Java's ServiceLoader mechanism. This allows you to:

- Create custom security tests tailored to your needs
- Override built-in tests with your own implementations
- Extend the scanner without modifying the core codebase

## Creating a Custom Test

### 1. Create a Test Class

Implement the `VulnerabilityTest` interface or extend `BaseVulnerabilityTest`:

```java
package dev.ua.ikeepcalm.vynce.plugins.custom;

import dev.ua.ikeepcalm.vynce.core.model.ScanContext;
import dev.ua.ikeepcalm.vynce.core.model.Vulnerability;
import dev.ua.ikeepcalm.vynce.core.model.source.Severity;
import dev.ua.ikeepcalm.vynce.core.model.source.TestType;
import dev.ua.ikeepcalm.vynce.tests.BaseVulnerabilityTest;

public class CustomApiTest extends BaseVulnerabilityTest {

    @Override
    public TestType getTestType() {
        // Return the test type this plugin implements
        return TestType.CUSTOM;
    }

    @Override
    protected void runTests(ScanContext context) throws Exception {
        // Your custom test logic here
        addVulnerability(new Vulnerability(
            Severity.HIGH,
            "Custom Vulnerability",
            "Description of the issue",
            context.getTargetUrl(),
            "attack payload"
        ));
    }
}
```

### 2. Register the Plugin

Create a file at `src/main/resources/META-INF/services/dev.ua.ikeepcalm.vynce.tests.VulnerabilityTest` containing:

```
dev.ua.ikeepcalm.vynce.plugins.custom.CustomApiTest
```

### 3. Build and Deploy

```bash
# Build the plugin JAR
./gradlew :vynce-plugins:build

# Copy to Vynce's classpath
cp vynce-plugins/build/libs/vynce-plugins-1.0.0.jar /path/to/vynce/plugins/
```

### 4. Run Vynce

The plugin will be automatically discovered and loaded:

```bash
java -cp "vynce-1.0.0-all.jar:plugins/*" dev.ua.ikeepcalm.vynce.VynceApplication scan https://target.com
```

## Example Plugins Included

- **GraphQLTest**: Tests for GraphQL-specific vulnerabilities
- **JWTTest**: JWT token security validation

## Plugin Development Tips

1. **Use BaseVulnerabilityTest**: It provides helper methods for common tasks
2. **Access the Crawler**: Use `context.getCrawler()` to access discovered URLs and forms
3. **Leverage HTTP Client**: Use `context.getHttpClient()` for making requests
4. **Add Logging**: Use `ConsoleUI.debug()` for debugging output
5. **Handle Exceptions**: Wrap your logic in try-catch to prevent crashes

## Distribution

You can distribute your plugin as a JAR file. Users just need to add it to the classpath.
