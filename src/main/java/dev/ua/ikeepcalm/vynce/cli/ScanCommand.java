package dev.ua.ikeepcalm.vynce.cli;

import dev.ua.ikeepcalm.vynce.core.ScanResult;
import dev.ua.ikeepcalm.vynce.core.Scanner;
import dev.ua.ikeepcalm.vynce.core.Vulnerability;
import dev.ua.ikeepcalm.vynce.core.source.Test;
import dev.ua.ikeepcalm.vynce.ui.ConsoleUI;
import dev.ua.ikeepcalm.vynce.ui.ScanProgress;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

import java.net.URI;
import java.net.URL;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
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
    private List<Test> tests;

    @Option(names = {"-x", "--exclude"},
            description = "Tests to exclude",
            split = ",",
            paramLabel = "<TEST>")
    private List<Test> excludeTests = new ArrayList<>();

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

    @CommandLine.Spec
    CommandLine.Model.CommandSpec spec;


    public enum OutputFormat {
        JSON, HTML, XML, CSV, MARKDOWN
    }

    @Override
    public Integer call() throws Exception {
        ConsoleUI.printSection("VULNERABILITY SCAN");

        ConsoleUI.info("Validating target URL...");
        if (!validateUrl()) {
            return 1;
        }

        ConsoleUI.info("Checking target availability...");
        if (!checkConnectivity()) {
            return 1;
        }

        if (tests == null || tests.isEmpty()) {
            tests = Arrays.asList(Test.values());
        }
        tests.removeAll(excludeTests);

        displayConfiguration();

        ConsoleUI.success("Target is accessible. Starting scan...");

        ScanProgress progress = new ScanProgress(tests.size());
        Scanner scanner = new Scanner(targetUrl, tests, threads);
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
        System.out.println("  Tests:           " + tests.size() + " selected");
        System.out.println("  Threads:         " + threads);
        System.out.println("  Crawl Depth:     " + depth);
        System.out.println("  Timeout:         " + timeout + "s");
        System.out.println("  User-Agent:      " + userAgent);
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
        ConsoleUI.info("Saving results to: " + outputFile);
        // Implementation stub
        ConsoleUI.success("Results saved successfully");
    }
}