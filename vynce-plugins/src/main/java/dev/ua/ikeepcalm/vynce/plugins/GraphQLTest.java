package dev.ua.ikeepcalm.vynce.plugins;

import dev.ua.ikeepcalm.vynce.core.model.ScanContext;
import dev.ua.ikeepcalm.vynce.core.model.Vulnerability;
import dev.ua.ikeepcalm.vynce.core.model.source.Severity;
import dev.ua.ikeepcalm.vynce.core.model.source.TestType;
import dev.ua.ikeepcalm.vynce.tests.BaseVulnerabilityTest;
import okhttp3.MediaType;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;

import java.util.Arrays;
import java.util.List;

/**
 * Example custom plugin for testing GraphQL-specific vulnerabilities.
 * This demonstrates how to create a third-party test plugin for Vynce Scanner.
 */
public class GraphQLTest extends BaseVulnerabilityTest {

    private static final List<String> GRAPHQL_INTROSPECTION_QUERIES = Arrays.asList(
            "{\"query\":\"{__schema{types{name}}}\"}",
            "{\"query\":\"{__type(name:\\\"Query\\\"){fields{name}}}\"}",
            "{\"query\":\"query IntrospectionQuery{__schema{queryType{name}mutationType{name}subscriptionType{name}}}\"}",
            "{\"query\":\"{ __schema { types { name fields { name type { name kind ofType { name kind } } } } } }\"}"
    );

    private static final List<String> GRAPHQL_PATHS = Arrays.asList(
            "/graphql",
            "/api/graphql",
            "/v1/graphql",
            "/query",
            "/api/query"
    );

    @Override
    public TestType getTestType() {
        // For custom tests, you might want to add a new TestType
        // For this example, we'll reuse an existing one
        return TestType.SSRF;  // Replace with custom TestType in production
    }

    @Override
    protected void runTests(ScanContext context) throws Exception {
        // Test common GraphQL endpoints
        for (String path : GRAPHQL_PATHS) {
            String graphqlUrl = context.getTargetUrl() + path;
            testGraphQLIntrospection(context, graphqlUrl);
            testGraphQLBatchingAttacks(context, graphqlUrl);
        }
    }

    private void testGraphQLIntrospection(ScanContext context, String url) {
        for (String query : GRAPHQL_INTROSPECTION_QUERIES) {
            try {
                Request request = new Request.Builder()
                        .url(url)
                        .post(RequestBody.create(query, MediaType.parse("application/json")))
                        .addHeader("Content-Type", "application/json")
                        .build();

                Response response = context.getHttpClient().executeRequest(request);

                if (response.isSuccessful()) {
                    String body = response.body() != null ? response.body().string() : "";

                    // Check if introspection is enabled
                    if (body.contains("__schema") || body.contains("__type") || body.contains("queryType")) {
                        addVulnerability(new Vulnerability(
                                Severity.MEDIUM,
                                "GraphQL Introspection Enabled",
                                "GraphQL introspection is enabled, exposing schema information",
                                url,
                                query
                        ));
                        break;
                    }
                }
            } catch (Exception e) {
                // Ignore errors
            }
        }
    }

    private void testGraphQLBatchingAttacks(ScanContext context, String url) {
        String batchQuery = "[" +
                "{\"query\":\"{__typename}\"}," +
                "{\"query\":\"{__typename}\"}," +
                "{\"query\":\"{__typename}\"}," +
                "{\"query\":\"{__typename}\"}," +
                "{\"query\":\"{__typename}\"}" +
                "]";

        try {
            Request request = new Request.Builder()
                    .url(url)
                    .post(RequestBody.create(batchQuery, MediaType.parse("application/json")))
                    .addHeader("Content-Type", "application/json")
                    .build();

            long startTime = System.currentTimeMillis();
            Response response = context.getHttpClient().executeRequest(request);
            long duration = System.currentTimeMillis() - startTime;

            if (response.isSuccessful()) {
                String body = response.body() != null ? response.body().string() : "";

                // Check if batching is allowed (response contains multiple results)
                if (body.contains("\"data\"") && body.split("\"data\"").length > 2) {
                    addVulnerability(new Vulnerability(
                            Severity.LOW,
                            "GraphQL Query Batching Allowed",
                            "GraphQL endpoint allows query batching, which could be abused for DoS attacks",
                            url,
                            "Batch query with 5 operations"
                    ));
                }
            }
        } catch (Exception e) {
            // Ignore errors
        }
    }
}
