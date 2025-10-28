# Table of Contents

- Project Overview
- Architecture Design
- Project Structure
- Implementation Roadmap
- Core Components Development
- Vulnerability Detection Modules
- Testing Strategy
- Deployment & Usage

# Project Overview

## Goals

- Build a modular CLI-based web vulnerability scanner in Java
- Implement detection for common vulnerabilities (SQL injection, XSS, CSRF, etc.)
- Provide extensible plugin architecture for adding new tests
- Generate comprehensive reports in multiple formats
- Follow specifications from technical documentation

## Technology Stack

- Language: Java 21
- Build Tool: Gradle 8.14
- CLI Framework: Picocli 4.7.5
- HTTP Client: OkHttp 4.12.0
- HTML Parsing: JSoup 1.17.2
- JSON Processing: Jackson 2.16.1
- Progress Display: ProgressBar 0.10.0
  -Testing: JUnit 5, Mockito

## Architecture Design

```
┌─────────────────────────────────────────────────────────┐
│                     CLI Interface                        │
│                    (Command Pattern)                     │
└────────────────┬────────────────────────────────────────┘
│
┌────────────────▼────────────────────────────────────────┐
│                    Core Scanner Engine                   │
│              (Strategy + Template Method)                │
└────────────────┬────────────────────────────────────────┘
│
┌────────────────▼────────────────────────────────────────┐
│                  Vulnerability Tests                     │
│                  (Plugin Architecture)                   │
├──────────┬──────────┬──────────┬──────────┬───────────┤
│   SQL    │   XSS    │   CSRF   │   SSRF   │    ...    │
└──────────┴──────────┴──────────┴──────────┴───────────┘
```

### Component Responsibilities

| Component        | Responsibility                                         |
|------------------|--------------------------------------------------------|
| CLI Layer        | User interaction, command parsing, output formatting   |
| Scanner Core     | Orchestration, thread management, result aggregation   |
| Test Plugins     | Individual vulnerability detection logic               |
| HTTP Engine      | Request handling, response parsing, session management |
| Report Generator | Result formatting and export                           |

## Project Structure

```
vynce-scanner/
├── build.gradle.kts
├── settings.gradle.kts
├── README.md
├── docs/
│   ├── ARCHITECTURE.md
│   ├── CONTRIBUTING.md
│   └── API.md
├── src/
│   ├── main/
│   │   ├── java/
│   │   │   └── dev/ua/ikeepcalm/vynce
│   │   │       ├── VulnScanApplication.java
│   │   │       ├── cli/                      # CLI commands
│   │   │       │   ├── MainCommand.java
│   │   │       │   ├── ScanCommand.java
│   │   │       │   ├── ReportCommand.java
│   │   │       │   └── validators/
│   │   │       │       └── UrlValidator.java
│   │   │       ├── core/                     # Core engine
│   │   │       │   ├── Scanner.java
│   │   │       │   ├── ScanConfig.java
│   │   │       │   ├── ScanContext.java
│   │   │       │   └── ThreadPoolManager.java
│   │   │       ├── http/                     # HTTP handling
│   │   │       │   ├── HttpClient.java
│   │   │       │   ├── RequestBuilder.java
│   │   │       │   ├── ResponseAnalyzer.java
│   │   │       │   └── CookieManager.java
│   │   │       ├── plugins/                  # Plugin system
│   │   │       │   ├── PluginLoader.java
│   │   │       │   ├── VulnerabilityTest.java
│   │   │       │   └── TestResult.java
│   │   │       ├── tests/                    # Vulnerability tests
│   │   │       │   ├── sql/
│   │   │       │   │   ├── SqlInjectionTest.java
│   │   │       │   │   └── payloads.json
│   │   │       │   ├── xss/
│   │   │       │   │   ├── XssTest.java
│   │   │       │   │   └── payloads.json
│   │   │       │   ├── csrf/
│   │   │       │   │   └── CsrfTest.java
│   │   │       │   └── headers/
│   │   │       │       └── SecurityHeadersTest.java
│   │   │       ├── crawler/                  # Web crawler
│   │   │       │   ├── WebCrawler.java
│   │   │       │   ├── LinkExtractor.java
│   │   │       │   └── FormAnalyzer.java
│   │   │       ├── report/                   # Report generation
│   │   │       │   ├── ReportGenerator.java
│   │   │       │   ├── HtmlReporter.java
│   │   │       │   ├── JsonReporter.java
│   │   │       │   └── templates/
│   │   │       └── ui/                       # UI utilities
│   │   │           ├── ConsoleUI.java
│   │   │           └── ProgressTracker.java
│   │   └── resources/
│   │       ├── logback.xml
│   │       ├── payloads/                     # Attack payloads
│   │       │   ├── sql-injections.json
│   │       │   ├── xss-vectors.json
│   │       │   └── common-passwords.txt
│   │       └── templates/                    # Report templates
│   │           └── report.html
│   └── test/
│       └── java/
│           └── com/vulnscan/
│               ├── core/
│               └── tests/
└── gradle/
└── libs.versions.toml
```

## Implementation Roadmap

# Phase 1: Foundation (Week 1)

- [ ] Set up project structure
- [ ] Configure Gradle build
- [ ] Implement CLI framework with Picocli
- [ ] Create basic UI\/UX with colored output
- [ ] Implement URL validation and connectivity check

### Phase 2: Core Engine (Week 2)

- [ ] Build HTTP client wrapper with OkHttp
- [ ] Implement thread pool management
- [ ] Create scan context and configuration
- [ ] Build plugin loader mechanism
- [ ] Implement result aggregation

### Phase 3: Web Crawler (Week 3)

- [ ] Implement basic web crawler
- [ ] Extract links and forms
- [ ] Build sitemap generator
- [ ] Handle different content types
- [ ] Implement crawl depth control

### Phase 4: Vulnerability Tests (Weeks 4-5)

- [ ] SQL Injection detection
- [ ] XSS detection
- [ ] CSRF detection
- [ ] Security headers analysis
- [ ] Directory traversal detection
- [ ] Open redirect detection

### Phase 5: Reporting (Week 6)

- [ ] JSON report generator
- [ ] HTML report with visualizations
- [ ] CSV export
- [ ] Integration with CI\/CD pipelines

### Phase 6: Polish & Testing (Week 7)

- [ ] Unit tests
- [ ] Integration tests
- [ ] Performance optimization
- [ ] Documentation
- [ ] Docker containerization

# Core Components Development

1. HTTP Client Implementation

```java
package com.vulnscan.http;

import okhttp3.*;

import java.io.IOException;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.TimeUnit;

public class VulnScanHttpClient {
    private final OkHttpClient client;
    private final CookieJar cookieJar;

    public VulnScanHttpClient(ScanConfig config) {
        this.cookieJar = new MemoryCookieJar();
        this.client = new OkHttpClient.Builder()
                .connectTimeout(config.getTimeout(), TimeUnit.SECONDS)
                .readTimeout(config.getTimeout(), TimeUnit.SECONDS)
                .followRedirects(config.isFollowRedirects())
                .cookieJar(cookieJar)
                .addInterceptor(new UserAgentInterceptor(config.getUserAgent()))
                .addInterceptor(new RateLimitInterceptor(config.getRequestDelay()))
                .build();
    }

    public Response get(String url, Map<String, String> headers) throws IOException {
        Request.Builder builder = new Request.Builder().url(url);
        headers.forEach(builder::addHeader);
        return client.newCall(builder.build()).execute();
    }

    public Response post(String url, Map<String, String> params,
                         Map<String, String> headers) throws IOException {
        FormBody.Builder formBuilder = new FormBody.Builder();
        params.forEach(formBuilder::add);

        Request.Builder requestBuilder = new Request.Builder()
                .url(url)
                .post(formBuilder.build());
        headers.forEach(requestBuilder::addHeader);

        return client.newCall(requestBuilder.build()).execute();
    }
}
```

2. Plugin System

```java
package com.vulnscan.plugins;

import java.util.ServiceLoader;
import java.util.List;
import java.util.ArrayList;

public class PluginLoader {
    private static final ServiceLoader<VulnerabilityTest> loader =
            ServiceLoader.load(VulnerabilityTest.class);

    public static List<VulnerabilityTest> loadTests(List<TestType> enabledTests) {
        List<VulnerabilityTest> tests = new ArrayList<>();

        for (VulnerabilityTest test : loader) {
            if (enabledTests.contains(test.getType())) {
                tests.add(test);
            }
        }

        // Load built-in tests if no plugins found
        if (tests.isEmpty()) {
            tests.addAll(loadBuiltInTests(enabledTests));
        }

        return tests;
    }

    private static List<VulnerabilityTest> loadBuiltInTests(List<TestType> types) {
        List<VulnerabilityTest> tests = new ArrayList<>();

        for (TestType type : types) {
            switch (type) {
                case SQL -> tests.add(new SqlInjectionTest());
                case XSS -> tests.add(new XssTest());
                case CSRF -> tests.add(new CsrfTest());
                case HEADERS -> tests.add(new SecurityHeadersTest());
                // Add more tests
            }
        }

        return tests;
    }
}
```

# Vulnerability Detection Modules

1. SQL Injection Detection

```java
package com.vulnscan.tests.sql;

import com.vulnscan.plugins.BaseVulnerabilityTest;

import java.util.List;
import java.util.ArrayList;

public class SqlInjectionTest extends BaseVulnerabilityTest {
    private static final List<String> PAYLOADS = List.of(
            "' OR '1'='1",
            "\" OR \"1\"=\"1",
            "' OR '1'='1' --",
            "' OR '1'='1' /*",
            "admin' --",
            "' UNION SELECT NULL--",
            "' AND 1=CONVERT(int, (SELECT @@version))--",
            "1' AND '1' LIKE '1",
            "' WAITFOR DELAY '00:00:05'--",
            "'; DROP TABLE users--"
    );

    @Override
    public TestResult execute(ScanContext context) {
        TestResult result = new TestResult(TestType.SQL);
        List<String> urls = context.getCrawler().getUrlsWithParams();

        for (String url : urls) {
            Map<String, String> params = extractParams(url);

            for (Map.Entry<String, String> param : params.entrySet()) {
                for (String payload : PAYLOADS) {
                    if (testPayload(url, param.getKey(), payload, context)) {
                        result.addVulnerability(new Vulnerability(
                                Severity.HIGH,
                                "SQL Injection",
                                "Parameter '" + param.getKey() + "' is vulnerable to SQL injection",
                                url,
                                payload
                        ));
                        break; // One vulnerability per parameter is enough
                    }
                }
            }
        }

        return result;
    }

    private boolean testPayload(String url, String param, String payload,
                                ScanContext context) {
        try {
            // Test 1: Error-based detection
            String testUrl = injectPayload(url, param, payload);
            Response response = context.getHttpClient().get(testUrl);
            String body = response.body().string();

            if (containsSqlError(body)) {
                return true;
            }

            // Test 2: Boolean-based blind
            String truePayload = param + "' AND '1'='1";
            String falsePayload = param + "' AND '1'='2";

            Response trueResponse = context.getHttpClient().get(
                    injectPayload(url, param, truePayload));
            Response falseResponse = context.getHttpClient().get(
                    injectPayload(url, param, falsePayload));

            if (significantDifference(trueResponse, falseResponse)) {
                return true;
            }

            // Test 3: Time-based blind
            String timePayload = param + "' WAITFOR DELAY '00:00:03'--";
            long startTime = System.currentTimeMillis();
            context.getHttpClient().get(injectPayload(url, param, timePayload));
            long duration = System.currentTimeMillis() - startTime;

            if (duration > 3000) {
                return true;
            }

        } catch (Exception e) {
            // Log error
        }

        return false;
    }

    private boolean containsSqlError(String body) {
        String[] errorPatterns = {
                "SQL syntax",
                "mysql_fetch",
                "ORA-[0-9]{5}",
                "PostgreSQL.*ERROR",
                "warning.*\\Wmysql_",
                "valid MySQL result",
                "mssql_query()",
                "Unclosed quotation mark",
                "Microsoft OLE DB Provider for ODBC Drivers"
        };

        for (String pattern : errorPatterns) {
            if (body.matches("(?i).*" + pattern + ".*")) {
                return true;
            }
        }
        return false;
    }
}
```

2. XSS Detection

```java
package com.vulnscan.tests.xss;

public class XssTest extends BaseVulnerabilityTest {
    private static final List<String> XSS_PAYLOADS = List.of(
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<body onload=alert('XSS')>",
            "<iframe src=javascript:alert('XSS')>",
            "'><script>alert(String.fromCharCode(88,83,83))</script>",
            "<input type=\"text\" value=\"\" onclick=\"alert('XSS')\" />",
            "<marquee onstart=alert('XSS')>",
            "<details open ontoggle=alert('XSS')>"
    );

    @Override
    public TestResult execute(ScanContext context) {
        TestResult result = new TestResult(TestType.XSS);

        // Test reflected XSS in URL parameters
        testReflectedXss(context, result);

        // Test stored XSS in forms
        testStoredXss(context, result);

        // Test DOM-based XSS
        testDomXss(context, result);

        return result;
    }

    private void testReflectedXss(ScanContext context, TestResult result) {
        for (String url : context.getCrawler().getUrlsWithParams()) {
            Map<String, String> params = extractParams(url);

            for (String param : params.keySet()) {
                for (String payload : XSS_PAYLOADS) {
                    String encodedPayload = URLEncoder.encode(payload, StandardCharsets.UTF_8);
                    String testUrl = injectPayload(url, param, encodedPayload);

                    try {
                        Response response = context.getHttpClient().get(testUrl);
                        String body = response.body().string();

                        // Check if payload is reflected without encoding
                        if (body.contains(payload) ||
                            body.contains(payload.replace("'", "\"")) ||
                            body.contains(payload.replace("\"", "'"))) {

                            result.addVulnerability(new Vulnerability(
                                    Severity.HIGH,
                                    "Reflected XSS",
                                    "Parameter '" + param + "' is vulnerable to XSS",
                                    url,
                                    payload
                            ));
                            break;
                        }
                    } catch (Exception e) {
                        // Log error
                    }
                }
            }
        }
    }
}
```

3. Security Headers Test

```java
package com.vulnscan.tests.headers;

public class SecurityHeadersTest extends BaseVulnerabilityTest {
    private static final Map<String, String> REQUIRED_HEADERS = Map.of(
            "X-Frame-Options", "DENY or SAMEORIGIN",
            "X-Content-Type-Options", "nosniff",
            "X-XSS-Protection", "1; mode=block",
            "Strict-Transport-Security", "max-age=31536000",
            "Content-Security-Policy", "Various directives"
    );

    @Override
    public TestResult execute(ScanContext context) {
        TestResult result = new TestResult(TestType.HEADERS);

        try {
            Response response = context.getHttpClient().get(context.getTargetUrl());
            Headers headers = response.headers();

            for (Map.Entry<String, String> required : REQUIRED_HEADERS.entrySet()) {
                String headerValue = headers.get(required.getKey());

                if (headerValue == null || headerValue.isEmpty()) {
                    result.addVulnerability(new Vulnerability(
                            Severity.MEDIUM,
                            "Missing Security Header",
                            "Missing header: " + required.getKey() +
                            " (recommended: " + required.getValue() + ")",
                            context.getTargetUrl(),
                            null
                    ));
                }
            }

            // Check for dangerous headers
            if (headers.get("Server") != null) {
                result.addVulnerability(new Vulnerability(
                        Severity.LOW,
                        "Information Disclosure",
                        "Server header exposes version information: " + headers.get("Server"),
                        context.getTargetUrl(),
                        null
                ));
            }

        } catch (Exception e) {
            // Log error
        }

        return result;
    }
}
```

# Deployment & Usage

## Building the Project

```bash
# Clone repository
git clone https://github.com/yourusername/vynce-scanner.git
cd vynce-scanner

# Build with Gradle
./gradlew build

# Create executable JAR
./gradlew shadowJar

# Run tests
./gradlew test
```

## Basic Usage

```bash
# Basic scan
java -jar vynce-scanner.jar scan https://target.com

# Scan with specific tests
java -jar vynce-scanner.jar scan https://target.com -t SQL,XSS --threads 10

# Scan with authentication
java -jar vynce-scanner.jar scan https://target.com \
  --auth-cookie "session=abc123" \
  --auth-header "Authorization: Bearer token"

# Generate HTML report
java -jar vynce-scanner.jar scan https://target.com \
  -o report.html -f HTML

# Scan with proxy
java -jar vynce-scanner.jar scan https://target.com \
  --proxy http://localhost:8080
  ```

# Next Steps & Enhancements

## Priority 1 (Essential)

- Implement remaining vulnerability tests
- Add authentication mechanisms (OAuth, JWT, Basic)
- Implement rate limiting to avoid DoS
- Add session management
- Create comprehensive test suite

## Priority 2 (Important)

- Add API scanning capabilities
- Implement WebSocket testing
- Add GraphQL vulnerability testing
- Create web UI dashboard
- Add CI/CD integration

## Priority 3 (Nice to Have)

- Machine learning for false positive reduction
- Distributed scanning capabilities
- Integration with bug bounty platforms
- Custom scripting language for tests
- Real-time collaboration features