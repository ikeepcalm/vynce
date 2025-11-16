package dev.ua.ikeepcalm.vynce.cli;

import dev.ua.ikeepcalm.vynce.core.model.ScanResult;
import dev.ua.ikeepcalm.vynce.core.service.Scanner;
import dev.ua.ikeepcalm.vynce.core.model.Vulnerability;
import dev.ua.ikeepcalm.vynce.core.model.source.TestType;
import dev.ua.ikeepcalm.vynce.report.ReportFactory;
import dev.ua.ikeepcalm.vynce.report.ReportGenerator;
import dev.ua.ikeepcalm.vynce.report.ReportManager;
import dev.ua.ikeepcalm.vynce.ui.ConsoleUI;
import dev.ua.ikeepcalm.vynce.ui.ScanProgress;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

import java.io.IOException;
import java.net.URI;
import java.net.URL;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.Callable;

@Command(
        name = "scan",
        description = "Scan a website for vulnerabilities",
        headerHeading = "@|bold,cyan Scan Configuration|@%n",
        optionListHeading = "%n@|bold,yellow Options|@:%n"
)
public class ScanCommand implements Callable<Integer> {

    @Parameters(index = "0",
            description = "Target URL to scan",
            paramLabel = "<URL>")
    private String targetUrl;

    @Option(names = {"-t", "--tests"},
            description = "Tests to run: ${COMPLETION-CANDIDATES} (default: all)",
            split = ",",
            paramLabel = "<TEST>")
    private List<TestType> testTypes;

    @Option(names = {"-x", "--exclude"},
            description = "Tests to exclude",
            split = ",",
            paramLabel = "<TEST>")
    private List<TestType> excludeTestTypes = new ArrayList<>();

    @Option(names = {"--threads"},
            description = "Number of threads (1-10, default: 5)",
            defaultValue = "5",
            paramLabel = "<N>")
    private int threads;

    @Option(names = {"-d", "--depth"},
            description = "Crawl depth (default: 3)",
            defaultValue = "3",
            paramLabel = "<N>")
    private int depth;

    @Option(names = {"-o", "--output"},
            description = "Output file",
            paramLabel = "<FILE>")
    private String outputFile;

    @Option(names = {"-f", "--format"},
            description = "Output format: ${COMPLETION-CANDIDATES}",
            defaultValue = "JSON")
    private OutputFormat format;

    @Option(names = {"--timeout"},
            description = "Request timeout in seconds",
            defaultValue = "30")
    private int timeout;

    @Option(names = {"--follow-redirects"},
            description = "Follow HTTP redirects",
            defaultValue = "true")
    private boolean followRedirects;

    @Option(names = {"--user-agent"},
            description = "Custom User-Agent",
            defaultValue = "Vynce Scanner/1.0")
    private String userAgent;

    @Option(names = {"--delay"},
            description = "Delay between requests in milliseconds (default: 0)",
            defaultValue = "0",
            paramLabel = "<MS>")
    private int requestDelay;

    @CommandLine.Spec
    CommandLine.Model.CommandSpec spec;

    @CommandLine.ParentCommand
    private MainCommand parent;

    public enum OutputFormat {
        JSON, HTML, MARKDOWN
    }

    @Override
    public Integer call() throws Exception {
        // Set verbose mode from parent command
        if (parent != null && parent.verbose) {
            ConsoleUI.setVerbose(true);
        }

        ConsoleUI.printSection("VULNERABILITY SCAN");

        ConsoleUI.info("Validating target URL...");
        if (!validateUrl()) {
            return 1;
        }

        ConsoleUI.info("Checking target availability...");
        if (!checkConnectivity()) {
            return 1;
        }

        if (testTypes == null || testTypes.isEmpty()) {
            testTypes = Arrays.asList(TestType.values());
        }
        testTypes.removeAll(excludeTestTypes);

        displayConfiguration();

        ConsoleUI.success("Target is accessible. Starting scan...");

        // Build scan configuration
        ScanConfig config = ScanConfig.builder()
                .threads(threads)
                .crawlDepth(depth)
                .timeout(timeout)
                .followRedirects(followRedirects)
                .userAgent(userAgent)
                .requestDelay(requestDelay)
                .build();

        // Setup graceful shutdown
        ScanProgress progress = new ScanProgress(testTypes.size());
        Scanner scanner = new Scanner(targetUrl, testTypes, config);

        setupShutdownHook(scanner, progress);

        ScanResult result = scanner.scanWithProgress(progress);

        displayResults(result);

        if (outputFile != null) {
            saveResults(result);
        }

        return 0;
    }

    private boolean validateUrl() {
        try {
            URL url = URI.create(targetUrl).toURL();
            if (!targetUrl.startsWith("http://") && !targetUrl.startsWith("https://")) {
                ConsoleUI.error("URL must start with http:// or https://");
                return false;
            }
            ConsoleUI.success("URL is valid: " + targetUrl);
            return true;
        } catch (Exception e) {
            ConsoleUI.error("Invalid URL: " + e.getMessage());
            return false;
        }
    }

    private void displayConfiguration() {
        ConsoleUI.printSubSection("Scan Configuration");
        System.out.println("  Target:          " + targetUrl);
        System.out.println("  Tests:           " + testTypes.size() + " selected");
        System.out.println("  Threads:         " + threads);
        System.out.println("  Crawl Depth:     " + depth);
        System.out.println("  Timeout:         " + timeout + "s");
        System.out.println("  Request Delay:   " + requestDelay + "ms");
        System.out.println("  User-Agent:      " + userAgent);
    }

    private void setupShutdownHook(Scanner scanner, ScanProgress progress) {
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            ConsoleUI.warning("\nScan interrupted by user. Cleaning up...");
            scanner.stop();
            progress.complete();
            ConsoleUI.info("Scan stopped. Partial results may be available.");
        }));
    }

    private boolean checkConnectivity() {
        try (HttpClient client = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NORMAL).build()) {

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(new URI(targetUrl))
                    .header("User-Agent", userAgent)
                    .timeout(java.time.Duration.ofSeconds(5))
                    .build();

            HttpResponse<String> response = client.send(request,
                    HttpResponse.BodyHandlers.ofString());

            ConsoleUI.success("Target responded with status: " + response.statusCode());
            return true;
        } catch (Exception e) {
            ConsoleUI.error("Failed to connect: " + e.getMessage());
            ConsoleUI.warning("Please check if the target is accessible");
            return false;
        }
    }

    private void displayResults(ScanResult result) {
        ConsoleUI.printSection("SCAN RESULTS");

        System.out.println("Scan Duration: " + result.getDuration() + "ms");
        System.out.println("Tests Performed: " + result.getTestCount());
        System.out.println();

        ConsoleUI.printSubSection("Vulnerabilities Found");

        if (result.getVulnerabilities().isEmpty()) {
            ConsoleUI.success("No vulnerabilities detected!");
        } else {
            for (Vulnerability vuln : result.getVulnerabilities()) {
                ConsoleUI.vulnerability(
                        vuln.getType(),
                        vuln.getSeverity(),
                        vuln.getDescription()
                );
            }

            System.out.println("\nSummary:");
            System.out.println("  Critical: " + result.getCriticalCount());
            System.out.println("  High:     " + result.getHighCount());
            System.out.println("  Medium:   " + result.getMediumCount());
            System.out.println("  Low:      " + result.getLowCount());
        }
    }

    private void saveResults(ScanResult result) {
        try {
            // Save to managed reports directory
            ReportManager manager = new ReportManager();
            String reportId = manager.saveReport(result, targetUrl);

            if (reportId != null) {
                ConsoleUI.success("Report saved with ID: " + reportId);
                ConsoleUI.info("View it with: vynce report view " + reportId);
            }

            // Also save to user-specified file if provided
            ConsoleUI.info("Generating " + format.name() + " report...");

            // Map OutputFormat to ReportFactory.ReportFormat
            ReportFactory.ReportFormat reportFormat = switch (format) {
                case JSON -> ReportFactory.ReportFormat.JSON;
                case HTML -> ReportFactory.ReportFormat.HTML;
                case MARKDOWN -> ReportFactory.ReportFormat.MARKDOWN;
            };

            ReportGenerator generator = ReportFactory.getGenerator(reportFormat);
            String reportContent = generator.generate(result);

            // Determine output file name
            String fileName = outputFile;
            if (!fileName.contains(".")) {
                fileName += "." + generator.getFileExtension();
            }

            // Write report to file
            Path outputPath = Path.of(fileName);
            Files.writeString(outputPath, reportContent);

            ConsoleUI.success("Report also saved to: " + outputPath.toAbsolutePath());
        } catch (IOException e) {
            ConsoleUI.error("Failed to save report: " + e.getMessage());
        }
    }
}