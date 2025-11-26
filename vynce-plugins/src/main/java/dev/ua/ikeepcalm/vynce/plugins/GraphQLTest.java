package dev.ua.ikeepcalm.vynce.plugins;

import dev.ua.ikeepcalm.vynce.core.model.ScanContext;
import dev.ua.ikeepcalm.vynce.core.model.source.Severity;
import dev.ua.ikeepcalm.vynce.core.model.source.TestType;
import dev.ua.ikeepcalm.vynce.tests.BaseVulnerabilityTest;
import dev.ua.ikeepcalm.vynce.ui.ConsoleUI;
import okhttp3.MediaType;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;

import java.util.Arrays;
import java.util.List;


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
        return TestType.CUSTOM;
    }

    @Override
    public String getTestName() {
        return "GraphQL Security";
    }

    @Override
    protected int estimateTestSteps(ScanContext context) {
        return GRAPHQL_PATHS.size() * (GRAPHQL_INTROSPECTION_QUERIES.size() + 1);
    }

    @Override
    protected void runTests(ScanContext context) throws Exception {
        for (String path : GRAPHQL_PATHS) {
            String graphqlUrl = context.getTargetUrl() + path;
            ConsoleUI.debug("Testing GraphQL path: " + path);

            testGraphQLIntrospection(context, graphqlUrl);
            testGraphQLBatchingAttacks(context, graphqlUrl);
        }
    }

    private void testGraphQLIntrospection(ScanContext context, String url) {
        for (String query : GRAPHQL_INTROSPECTION_QUERIES) {
            advanceProgress("Introspection: " + url);
            try {
                Request request = new Request.Builder()
                        .url(url)
                        .post(RequestBody.create(query, MediaType.parse("application/json")))
                        .addHeader("Content-Type", "application/json")
                        .build();

                try (Response response = context.getHttpClient().executeRequest(request)) {
                    if (response.isSuccessful()) {
                        String body = context.getHttpClient().getBodyAsString(response);

                        if (body.contains("__schema") || body.contains("__type") || body.contains("queryType")) {
                            addVulnerability(createVulnerability(
                                    Severity.MEDIUM,
                                    "GraphQL Introspection Enabled",
                                    "GraphQL introspection is enabled, exposing schema information",
                                    url,
                                    query
                            ));
                            ConsoleUI.debug("GraphQL introspection vulnerability found at: " + url);
                            break;
                        }
                    }
                }
            } catch (Exception e) {
                ConsoleUI.debug("Error testing GraphQL introspection: " + e.getMessage());
            }
        }
    }

    private void testGraphQLBatchingAttacks(ScanContext context, String url) {
        advanceProgress("Batching: " + url);

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
            try (Response response = context.getHttpClient().executeRequest(request)) {

                if (response.isSuccessful()) {
                    String body = context.getHttpClient().getBodyAsString(response);

                    if (body.contains("\"data\"") && body.split("\"data\"").length > 2) {
                        addVulnerability(createVulnerability(
                                Severity.LOW,
                                "GraphQL Query Batching Allowed",
                                "GraphQL endpoint allows query batching, which could be abused for DoS attacks",
                                url,
                                "Batch query with 5 operations"
                        ));
                        ConsoleUI.debug("GraphQL batching vulnerability found at: " + url);
                    }
                }
            }
        } catch (Exception e) {
            ConsoleUI.debug("Error testing GraphQL batching: " + e.getMessage());
        }
    }
}
