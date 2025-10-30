package dev.ua.ikeepcalm.vynce.tests.impl;

import dev.ua.ikeepcalm.vynce.core.model.ScanContext;
import dev.ua.ikeepcalm.vynce.core.model.source.TestType;
import dev.ua.ikeepcalm.vynce.tests.BaseVulnerabilityTest;
import dev.ua.ikeepcalm.vynce.ui.ConsoleUI;

public class CorsTest extends BaseVulnerabilityTest {

    @Override
    public TestType getTestType() {
        return TestType.CORS;
    }

    @Override
    protected void runTests(ScanContext context) throws Exception {
        // TODO: Implement CORS misconfiguration detection
        ConsoleUI.error("CORS test not yet implemented");
    }
}
