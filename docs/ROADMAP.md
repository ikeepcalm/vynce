# Table of Contents

- **Current Status & Progress**
- Project Overview
- Architecture Design
- Project Structure
- Implementation Roadmap
- Core Components Development
- Vulnerability Detection Modules
- Testing Strategy
- Deployment & Usage

---

# Current Status & Progress

**Last Updated:** October 30, 2025

## ✅ What's Working

- **Core Scanner Engine:** Fully functional with concurrent testType execution
- **HTTP Client:** OkHttp-based wrapper with interceptors and configuration
- **CLI Interface:** Picocli-based commands with progress bars and colored output
- **Vulnerability Tests (4/12):**
  - SQL Injection (error, boolean, time-based detection)
  - XSS (reflected, attribute, JavaScript context)
  - CSRF (form token validation)
  - Security Headers (7 headers + information disclosure)
- **Payload System:** JSON-based payload loading with 100+ attack vectors
- **Build System:** Gradle with shadow JAR compilation

## 🚧 In Progress

- Remaining 8 vulnerability testType implementations (stubs created)
- Web crawler for automatic endpoint discovery
- Report generation (JSON, HTML, CSV, Markdown)

## 📊 Completion Status

| Phase | Status | Completion |
|-------|--------|-----------|
| Phase 1: Foundation | ✅ Complete | 100% |
| Phase 2: Core Engine | ✅ Complete | 100% |
| Phase 3: Web Crawler | ⏸️ Pending | 0% |
| Phase 4: Vulnerability Tests | 🚧 In Progress | 33% (4/12 testTypes) |
| Phase 5: Reporting | ⏸️ Pending | 0% |
| Phase 6: Polish & Testing | ⏸️ Pending | 0% |

**Overall Project Completion: ~40%**

---

# Project Overview

## Goals

- Build a modular CLI-based web vulnerability scanner in Java
- Implement detection for common vulnerabilities (SQL injection, XSS, CSRF, etc.)
- Provide extensible plugin architecture for adding new testTypes
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

### Actual Implementation

```
Vynce/
├── build.gradle.kts
├── settings.gradle.kts
├── README.md
├── docs/
│   └── ROADMAP.md
├── src/
│   ├── main/
│   │   ├── java/dev/ua/ikeepcalm/vynce/
│   │   │   ├── VynceApplication.java         # Main entry point
│   │   │   ├── cli/                          # CLI commands ✅
│   │   │   │   ├── MainCommand.java
│   │   │   │   ├── ScanCommand.java
│   │   │   │   └── report/
│   │   │   │       ├── ReportCommand.java
│   │   │   │       ├── ReportListCommand.java
│   │   │   │       ├── ReportViewCommand.java
│   │   │   │       └── ReportExportCommand.java
│   │   │   ├── core/                         # Core engine ✅
│   │   │   │   ├── Scanner.java              # Orchestrates testType execution
│   │   │   │   ├── ScanConfig.java           # Configuration builder
│   │   │   │   ├── ScanContext.java          # Shared testType context
│   │   │   │   ├── ScanResult.java           # Result aggregation
│   │   │   │   ├── Vulnerability.java        # Vulnerability model
│   │   │   │   └── source/
│   │   │   │       ├── Test.java             # Test type enum
│   │   │   │       └── Severity.java         # Severity enum
│   │   │   ├── http/                         # HTTP handling ✅
│   │   │   │   ├── VynceHttpClient.java      # OkHttp wrapper
│   │   │   │   ├── UserAgentInterceptor.java
│   │   │   │   └── RateLimitInterceptor.java
│   │   │   ├── testTypes/                        # Test framework ✅
│   │   │   │   ├── VulnerabilityTest.java    # Test interface
│   │   │   │   ├── BaseVulnerabilityTest.java
│   │   │   │   ├── TestFactory.java          # Factory pattern
│   │   │   │   └── impl/                     # Test implementations
│   │   │   │       ├── SqlInjectionTest.java      ✅
│   │   │   │       ├── XssTest.java               ✅
│   │   │   │       ├── CsrfTest.java              ✅
│   │   │   │       ├── SecurityHeadersTest.java   ✅
│   │   │   │       ├── SsrfTest.java              (stub)
│   │   │   │       ├── XxeTest.java               (stub)
│   │   │   │       ├── PathTraversalTest.java     (stub)
│   │   │   │       ├── CommandInjectionTest.java  (stub)
│   │   │   │       ├── LdapInjectionTest.java     (stub)
│   │   │   │       ├── XpathInjectionTest.java    (stub)
│   │   │   │       ├── CorsTest.java              (stub)
│   │   │   │       └── OpenRedirectTest.java      (stub)
│   │   │   ├── utils/                        # Utilities ✅
│   │   │   │   └── PayloadLoader.java        # JSON payload loader
│   │   │   └── ui/                           # UI utilities ✅
│   │   │       ├── ConsoleUI.java            # Colored output
│   │   │       └── ScanProgress.java         # Progress bars
│   │   └── resources/
│   │       ├── logback.xml
│   │       ├── payloads/                     # Attack payloads ✅
│   │       │   ├── sql-injection.json        # 60+ payloads
│   │       │   └── xss-vectors.json          # 40+ vectors
│   │       └── signatures/
│   │           └── default.json              (empty)
│   └── testType/
│       └── java/                             (no testTypes yet)
└── build/
    └── libs/
        └── Vynce-1.0.0-all.jar              # Executable JAR

Legend:
✅ = Fully implemented
(stub) = Interface created, implementation pending
```

### Planned vs Actual

**Differences from original plan:**
- Tests organized under `testTypes/impl/` instead of separate directories per testType
- PayloadLoader utility added for JSON payload management
- Report generation deferred to Phase 5
- Web crawler deferred to Phase 3

## Implementation Roadmap

### Phase 1: Foundation ✅ COMPLETED

- [x] Set up project structure
- [x] Configure Gradle build
- [x] Implement CLI framework with Picocli
- [x] Create basic UI/UX with colored output
- [x] Implement URL validation and connectivity check

### Phase 2: Core Engine ✅ COMPLETED

- [x] Build HTTP client wrapper with OkHttp
- [x] Implement thread pool management
- [x] Create scan context and configuration
- [x] Build plugin loader mechanism (TestFactory)
- [x] Implement result aggregation

**Implemented Components:**
- `VynceHttpClient` with UserAgent and RateLimit interceptors
- `ScanContext` for shared testType context
- `ScanConfig` builder pattern for configuration
- `TestFactory` for testType instantiation
- `BaseVulnerabilityTest` abstract base class
- `PayloadLoader` for JSON payload loading

### Phase 3: Web Crawler (Week 3) - PENDING

- [ ] Implement basic web crawler
- [ ] Extract links and forms
- [ ] Build sitemap generator
- [ ] Handle different content types
- [ ] Implement crawl depth control

### Phase 4: Vulnerability Tests (Weeks 4-5) - PARTIALLY COMPLETED

**Completed Tests:**
- [x] SQL Injection detection (error-based, boolean-based, time-based)
- [x] XSS detection (reflected, attribute-based, JavaScript context)
- [x] CSRF detection (form token validation)
- [x] Security headers analysis (7 headers + information disclosure)

**Pending Tests:**
- [ ] SSRF detection (stub created)
- [ ] XXE detection (stub created)
- [ ] Directory traversal detection (stub created)
- [ ] Path traversal detection (stub created)
- [ ] Command injection detection (stub created)
- [ ] LDAP injection detection (stub created)
- [ ] XPath injection detection (stub created)
- [ ] CORS misconfiguration detection (stub created)
- [ ] Open redirect detection (stub created)

**Payload Files Created:**
- `sql-injection.json`: 60+ payloads and error patterns
- `xss-vectors.json`: 40+ attack vectors

### Phase 5: Reporting (Week 6) - PENDING

- [ ] JSON report generator
- [ ] HTML report with visualizations
- [ ] CSV export
- [ ] Markdown export
- [ ] Integration with CI/CD pipelines

**Current Status:** Console output only

### Phase 6: Polish & Testing (Week 7) - PENDING

- [ ] Unit testTypes
- [ ] Integration testTypes
- [ ] Performance optimization
- [ ] Documentation
- [ ] Docker containerization

## Current Implementation Status

**Working Features:**
- ✅ CLI interface with Picocli
- ✅ HTTP client with OkHttp (interceptors, timeouts, redirects)
- ✅ Concurrent testType execution with thread pool
- ✅ Progress tracking with progress bars
- ✅ 4 fully functional vulnerability testTypes
- ✅ Payload loading from JSON files
- ✅ Console output with colored formatting
- ✅ Severity-based vulnerability categorization

**Next Steps:**
1. Implement web crawler for automatic endpoint discovery
2. Complete remaining vulnerability testTypes
3. Add report generation (JSON, HTML, CSV)
4. Write comprehensive testType suite
5. Add authentication support (OAuth, JWT, Basic Auth)

# Core Components Development

1. HTTP Client Implementation

```java
package com.vynce.http;

import okhttp3.*;

import java.io.IOException;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.TimeUnit;

public class vynceHttpClient {
    private final OkHttpClient client;
    private final CookieJar cookieJar;

    public vynceHttpClient(ScanConfig config) {
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
package com.vynce.plugins;

import java.util.ServiceLoader;
import java.util.List;
import java.util.ArrayList;

public class PluginLoader {
    private static final ServiceLoader<VulnerabilityTest> loader =
            ServiceLoader.load(VulnerabilityTest.class);

    public static List<VulnerabilityTest> loadTests(List<TestType> enabledTests) {
        List<VulnerabilityTest> testTypes = new ArrayList<>();

        for (VulnerabilityTest testType : loader) {
            if (enabledTests.contains(testType.getType())) {
                testTypes.add(testType);
            }
        }

        // Load built-in testTypes if no plugins found
        if (testTypes.isEmpty()) {
            testTypes.addAll(loadBuiltInTests(enabledTests));
        }

        return testTypes;
    }

    private static List<VulnerabilityTest> loadBuiltInTests(List<TestType> types) {
        List<VulnerabilityTest> testTypes = new ArrayList<>();

        for (TestType type : types) {
            switch (type) {
                case SQL -> testTypes.add(new SqlInjectionTest());
                case XSS -> testTypes.add(new XssTest());
                case CSRF -> testTypes.add(new CsrfTest());
                case HEADERS -> testTypes.add(new SecurityHeadersTest());
                // Add more testTypes
            }
        }

        return testTypes;
    }
}
```

# Vulnerability Detection Modules

1. SQL Injection Detection

```java
package com.vynce.testTypes.sql;

import com.vynce.plugins.BaseVulnerabilityTest;

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
package com.vynce.testTypes.xss;

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
package com.vynce.testTypes.headers;

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

# Run testTypes
./gradlew testType
```

## Basic Usage

```bash
# Basic scan
java -jar vynce-scanner.jar scan https://target.com

# Scan with specific testTypes
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

- Implement remaining vulnerability testTypes
- Add authentication mechanisms (OAuth, JWT, Basic)
- Implement rate limiting to avoid DoS
- Add session management
- Create comprehensive testType suite

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
- Custom scripting language for testTypes
- Real-time collaboration features