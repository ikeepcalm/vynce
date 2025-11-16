# Vynce Custom Test Plugins

This module demonstrates how to create custom vulnerability tests for Vynce Scanner using a simple plugin system.

## Overview

Vynce Scanner supports custom vulnerability tests through a dynamic JAR loading system. This allows you to:

- Create custom security tests tailored to your needs
- Override built-in tests with your own implementations
- Extend the scanner without modifying the core codebase
- Simply drop JAR files into a `plugins/` folder

## How Plugin Loading Works

Vynce automatically scans a `plugins/` directory for JAR files when it starts:

```
vynce.jar
plugins/
  ├── test1.jar
  └── test2.jar
```

When you run Vynce, it will:
1. Look for a `plugins/` folder next to the JAR
2. Load all JAR files from that folder
3. Scan each JAR for classes implementing `VulnerabilityTest`
4. Make those tests available for scanning

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
        return TestType.SSRF;  // You can override built-in tests
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

### 2. Build the Plugin

```bash
# Build the plugin JAR
./gradlew :vynce-plugins:build

# This creates: vynce-plugins/build/libs/vynce-plugins-1.0.0.jar
```

### 3. Deploy the Plugin

Simply copy the JAR to the `plugins/` folder:

```bash
# Create plugins folder next to vynce.jar
mkdir plugins

# Copy your plugin
cp vynce-plugins/build/libs/vynce-plugins-1.0.0.jar plugins/
```

### 4. Run Vynce

Just run Vynce normally - plugins are loaded automatically:

```bash
java -jar vynce-1.0.0-all.jar scan https://target.com
```

**Output:**
```
Loading plugins from: /path/to/plugins
Loaded 2 test(s) from vynce-plugins-1.0.0.jar
Total plugins loaded: 2 test(s) from 1 JAR(s)
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
