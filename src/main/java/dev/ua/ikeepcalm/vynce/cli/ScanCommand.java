package dev.ua.ikeepcalm.vynce.cli;

import dev.ua.ikeepcalm.vynce.core.model.ScanConfig;
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
        if (parent != null && parent.verbose) {
            ConsoleUI.setVerbose(true);
        }

        ConsoleUI.showBanner();

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

        Thread shutdownHook = setupShutdownHook(scanner, progress);

        ScanResult result = scanner.scanWithProgress(progress);

        // Remove shutdown hook after successful completion
        try {
            Runtime.getRuntime().removeShutdownHook(shutdownHook);
        } catch (IllegalStateException ignored) {
            // Hook already running or JVM shutting down
        }

        displayResults(result);

        // Always save to managed reports directory
        saveToReportsDirectory(result);

        // Additionally export to custom file if specified
        if (outputFile != null) {
            exportToCustomFile(result);
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
        System.out.println();
    }

    private Thread setupShutdownHook(Scanner scanner, ScanProgress progress) {
        Thread shutdownHook = new Thread(() -> {
            scanner.stop();
            progress.complete();
            ConsoleUI.warning("Scan interrupted by user. Cleaning up...");
            ConsoleUI.info("Scan stopped. Partial results may be available.");
        });
        Runtime.getRuntime().addShutdownHook(shutdownHook);
        return shutdownHook;
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
            System.out.println();
        }
    }

    /**
     * Save scan results to the managed reports directory (~/.vynce/reports)
     */
    private void saveToReportsDirectory(ScanResult result) {
        try {
            ReportManager manager = new ReportManager();
            String reportId = manager.saveReport(result, targetUrl);

            if (reportId != null) {
                ConsoleUI.success("Report saved with ID: " + reportId);

                // If format is not JSON, also save the formatted version
                if (format != OutputFormat.JSON) {
                    String formatName = format.name();
                    ReportFactory.ReportFormat reportFormat = switch (format) {
                        case HTML -> ReportFactory.ReportFormat.HTML;
                        case MARKDOWN -> ReportFactory.ReportFormat.MARKDOWN;
                        default -> ReportFactory.ReportFormat.JSON;
                    };

                    ReportGenerator generator = ReportFactory.getGenerator(reportFormat);
                    String reportContent = generator.generate(result);

                    // Save formatted version alongside JSON
                    Path formattedReport = manager.getReportsDirectory()
                        .resolve(reportId + "." + generator.getFileExtension());
                    Files.writeString(formattedReport, reportContent);

                    ConsoleUI.info("Also saved as " + formatName + " format");
                }

                ConsoleUI.info("View it with: vynce report view " + reportId);
            }
        } catch (Exception e) {
            ConsoleUI.error("Failed to save report to managed directory: " + e.getMessage());
        }
    }

    /**
     * Export scan results to a custom file in the specified format
     */
    private void exportToCustomFile(ScanResult result) {
        try {
            ConsoleUI.info("Exporting " + format.name() + " report to custom file...");

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

            ConsoleUI.success("Report exported to: " + outputPath.toAbsolutePath());
        } catch (IOException e) {
            ConsoleUI.error("Failed to export report: " + e.getMessage());
        }
    }
}